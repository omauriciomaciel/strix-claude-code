"""Docker sandbox management for penetration testing tools."""

import contextlib
import logging
import multiprocessing
import os
import secrets
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path
from typing import Any, cast

import docker
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container

logger = logging.getLogger(__name__)


def get_cpu_count(reserve: int = 2) -> int:
    """Get available CPU count, reserving some for the host system."""
    total = multiprocessing.cpu_count()
    available = max(1, total - reserve)  # At least 1 CPU for the sandbox
    return available

# Default strix sandbox image
DEFAULT_SANDBOX_IMAGE = "ghcr.io/usestrix/strix-sandbox:1.0.0"
HOST_GATEWAY_HOSTNAME = "host.docker.internal"
DOCKER_TIMEOUT = 60
# Caido always binds to this port *inside* the container (hardcoded in the
# image's docker-entrypoint.sh since 1.0.0 - no longer configurable via env).
CAIDO_CONTAINER_PORT = 48080
CONTAINER_HEALTH_RETRIES = 30
CONTAINER_HEALTH_REQUEST_TIMEOUT = 5


class SandboxError(Exception):
    """Error during sandbox operations."""
    pass


class Sandbox:
    """Manages Docker sandbox container for pen testing."""

    def __init__(
        self,
        image: str | None = None,
        scan_id: str | None = None,
        mount_docker_socket: bool = False,
    ):
        self.image = image or os.getenv("STRIX_IMAGE", DEFAULT_SANDBOX_IMAGE)
        self.scan_id = scan_id or f"scan-{secrets.token_hex(4)}"
        self.mount_docker_socket = mount_docker_socket or os.getenv("STRIX_MOUNT_DOCKER", "").lower() in ("1", "true", "yes")

        try:
            self.client = docker.from_env(timeout=DOCKER_TIMEOUT)
        except DockerException as e:
            raise SandboxError(
                "Docker is not available. Please ensure Docker is installed and running."
            ) from e

        self._container: Container | None = None
        self._caido_port: int | None = None

    def _find_available_port(self, exclude: set[int] | None = None) -> int:
        """Find an available port, optionally excluding some ports."""
        exclude = exclude or set()
        for _ in range(10):  # Try up to 10 times
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", 0))
                port = cast("int", s.getsockname()[1])
                if port not in exclude:
                    return port
        raise SandboxError("Could not find available port")

    def _exec_with_timeout(
        self, container: Container, cmd: str, timeout: int = DOCKER_TIMEOUT, **kwargs: Any
    ) -> Any:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(container.exec_run, cmd, **kwargs)
            try:
                return future.result(timeout=timeout)
            except FuturesTimeoutError:
                raise SandboxError(f"Command timed out: {cmd[:100]}...")

    def _resolve_docker_host(self) -> str:
        docker_host = os.getenv("DOCKER_HOST", "")
        if not docker_host:
            return "127.0.0.1"
        from urllib.parse import urlparse
        parsed = urlparse(docker_host)
        if parsed.scheme in ("tcp", "http", "https") and parsed.hostname:
            return parsed.hostname
        return "127.0.0.1"

    def ensure_image(self) -> None:
        """Pull sandbox image if not available."""
        try:
            self.client.images.get(self.image)
            logger.info(f"Image {self.image} is available")
        except ImageNotFound:
            logger.info(f"Pulling image {self.image}...")
            self.client.images.pull(self.image)
            logger.info(f"Image {self.image} pulled successfully")

    def start(self, local_sources: list[dict[str, str]] | None = None) -> dict[str, Any]:
        """Start the sandbox container and return connection info."""
        self.ensure_image()

        container_name = f"strix-cli-{self.scan_id}"

        # Clean up existing container
        try:
            existing = self.client.containers.get(container_name)
            logger.info(f"Removing existing container {container_name}")
            with contextlib.suppress(Exception):
                existing.stop(timeout=5)
            existing.remove(force=True)
            time.sleep(1)
        except NotFound:
            pass

        self._caido_port = self._find_available_port()

        # Get CPU count for parallel operations
        cpu_count = get_cpu_count()
        self._cpu_count = cpu_count

        logger.info(f"Starting container {container_name}")
        logger.info(f"  CPUs available: {cpu_count}")
        logger.info(f"  Caido proxy port: {self._caido_port}")
        logger.info(f"  Docker socket mounted: {self.mount_docker_socket}")

        # Build volumes list
        volumes = {}
        if self.mount_docker_socket:
            # Mount Docker socket for container/image scanning capabilities
            # This enables: docker inspect, docker images, trivy, grype, etc.
            docker_sock = "/var/run/docker.sock"
            if Path(docker_sock).exists():
                volumes[docker_sock] = {"bind": docker_sock, "mode": "rw"}
                logger.info(f"  Mounting Docker socket: {docker_sock}")
            else:
                logger.warning("Docker socket not found at /var/run/docker.sock")

        # Create and start container with all available CPUs.
        # No entrypoint override: the image's own docker-entrypoint.sh brings up
        # Caido, trusts the CA and configures the proxy before `exec "$@"`
        # hands off to our keep-alive command (same pattern strix's own
        # StrixDockerSandboxClient uses upstream).
        self._container = self.client.containers.run(
            self.image,
            command=["tail", "-f", "/dev/null"],
            detach=True,
            name=container_name,
            hostname=container_name,
            ports={f"{CAIDO_CONTAINER_PORT}/tcp": self._caido_port},
            cap_add=["NET_ADMIN", "NET_RAW"],
            labels={"strix-cli-scan-id": self.scan_id},
            # Allocate all CPUs to the container
            nano_cpus=cpu_count * 1_000_000_000,  # Docker uses nano CPUs
            volumes=volumes if volumes else None,
            environment={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
                # Pass CPU count for tools to use
                "STRIX_CPU_COUNT": str(cpu_count),
                "NMAP_THREADS": str(cpu_count * 4),  # nmap can use more threads than CPUs
                "FFUF_THREADS": str(cpu_count * 10),  # ffuf benefits from high concurrency
                "NUCLEI_THREADS": str(cpu_count * 5),  # nuclei template concurrency
                # Flag for Docker access inside container
                "DOCKER_HOST": "unix:///var/run/docker.sock" if self.mount_docker_socket else "",
            },
            extra_hosts={HOST_GATEWAY_HOSTNAME: "host-gateway"},
            tty=True,
        )

        # Wait for the entrypoint's Caido/CA/proxy setup to finish
        self._wait_for_ready()

        # Setup Docker access if socket is mounted
        if self.mount_docker_socket:
            self._setup_docker_access()

        # Copy local sources if provided
        if local_sources:
            self._copy_local_sources(local_sources)

        return {
            "container_id": self._container.id,
            "container_name": container_name,
            "caido_port": self._caido_port,
            "scan_id": self.scan_id,
            "cpu_count": cpu_count,
        }

    def _wait_for_ready(self) -> None:
        """Wait for the entrypoint to finish bringing up Caido + the proxy config.

        The entrypoint script runs synchronously before `exec "$@"` starts our
        `tail -f /dev/null` keep-alive, so polling Caido's GraphQL endpoint from
        the host doubles as a readiness probe for the whole entrypoint.
        """
        import httpx

        host = self._resolve_docker_host()
        graphql_url = f"http://{host}:{self._caido_port}/graphql/"
        logger.info(f"Waiting for Caido at {graphql_url}")

        for attempt in range(CONTAINER_HEALTH_RETRIES):
            try:
                with httpx.Client(trust_env=False, timeout=CONTAINER_HEALTH_REQUEST_TIMEOUT) as client:
                    response = client.get(graphql_url)
                    if response.status_code in (200, 400):
                        break
            except Exception as e:
                logger.debug(f"Caido health check attempt {attempt + 1}: {e}")
            time.sleep(min(2**attempt * 0.5, 5))
        else:
            raise SandboxError("Caido proxy failed to start in the sandbox container")

        # Entrypoint writes proxy.sh right after Caido comes up; give it a
        # moment to land so exec'd shells (which source it via profile.d) see it.
        for _ in range(CONTAINER_HEALTH_RETRIES):
            result = self._exec_with_timeout(
                self._container, "test -f /etc/profile.d/proxy.sh", user="root",
            )
            if result.exit_code == 0:
                return
            time.sleep(0.5)
        raise SandboxError("Sandbox container did not finish entrypoint setup in time")

    def _setup_docker_access(self) -> None:
        """Setup Docker CLI and socket permissions for container scanning."""
        if not self._container:
            return

        logger.info("Setting up Docker access...")

        # Fix Docker socket permissions so pentester user can access it
        # The host socket is often root:docker with 660 permissions
        self._container.exec_run(
            "chmod 666 /var/run/docker.sock",
            user="root",
        )
        logger.info("  Fixed Docker socket permissions")

        # Install Docker CLI (static binary - works on any distro)
        result = self._container.exec_run(
            "which docker",
            user="pentester",
        )
        if result.exit_code != 0:
            logger.info("  Installing Docker CLI...")
            install_result = self._container.exec_run(
                "bash -c '"
                "curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz -o /tmp/docker.tgz && "
                "tar -xzf /tmp/docker.tgz -C /tmp && "
                "mv /tmp/docker/docker /usr/local/bin/ && "
                "rm -rf /tmp/docker /tmp/docker.tgz && "
                "chmod +x /usr/local/bin/docker"
                "'",
                user="root",
            )
            if install_result.exit_code == 0:
                logger.info("  Docker CLI installed successfully")
            else:
                logger.warning(f"  Failed to install Docker CLI: {install_result.output.decode()}")
        else:
            logger.info("  Docker CLI already available")

        # Install trivy for container scanning
        result = self._container.exec_run(
            "which trivy",
            user="pentester",
        )
        if result.exit_code != 0:
            logger.info("  Installing trivy...")
            install_result = self._container.exec_run(
                "bash -c '"
                "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
                "'",
                user="root",
            )
            if install_result.exit_code == 0:
                logger.info("  Trivy installed successfully")
            else:
                logger.warning(f"  Failed to install trivy: {install_result.output.decode()}")
        else:
            logger.info("  Trivy already available")

        # Verify Docker connectivity
        result = self._container.exec_run(
            "docker ps",
            user="pentester",
        )
        if result.exit_code == 0:
            logger.info("  Docker connectivity verified")
        else:
            logger.warning(f"  Docker connectivity test failed: {result.output.decode()}")

    def _copy_local_sources(self, sources: list[dict[str, str]]) -> None:
        """Copy local directories to container workspace."""
        import tarfile
        from io import BytesIO

        if not self._container:
            return

        for idx, source in enumerate(sources, 1):
            source_path = source.get("source_path")
            if not source_path:
                continue

            local_path = Path(source_path).resolve()
            if not local_path.exists() or not local_path.is_dir():
                logger.warning(f"Path does not exist: {local_path}")
                continue

            target_name = source.get("workspace_subdir") or local_path.name or f"target_{idx}"
            logger.info(f"Copying {local_path} to /workspace/{target_name}")

            tar_buffer = BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                for item in local_path.rglob("*"):
                    if item.is_file():
                        rel_path = item.relative_to(local_path)
                        arcname = Path(target_name) / rel_path
                        tar.add(item, arcname=str(arcname))

            tar_buffer.seek(0)
            self._container.put_archive("/workspace", tar_buffer.getvalue())

        self._container.exec_run(
            "chown -R pentester:pentester /workspace && chmod -R 755 /workspace",
            user="root",
        )

    def stop(self) -> None:
        """Stop and remove the sandbox container."""
        if self._container:
            logger.info(f"Stopping container {self._container.name}")
            try:
                self._container.stop(timeout=10)
                self._container.remove(force=True)
            except Exception as e:
                logger.warning(f"Error stopping container: {e}")
            self._container = None

    def exec_command(self, command: str, user: str = "pentester") -> tuple[int, str]:
        """Execute a command in the sandbox."""
        if not self._container:
            raise SandboxError("Container not running")

        result = self._container.exec_run(command, user=user)
        return result.exit_code, result.output.decode()

    @property
    def is_running(self) -> bool:
        if not self._container:
            return False
        try:
            self._container.reload()
            return self._container.status == "running"
        except:
            return False
