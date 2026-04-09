"""Docker management tools for ZimaOS MCP Server."""

import json
import os

from config import ServerConfig
from security import SecurityManager
from tools.utils import make_response, run_docker as _run_docker


async def docker_ps(
    all: bool = False,
    filters: dict | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """List Docker containers.

    Args:
        all: Include stopped containers.
        filters: Docker filters dict (e.g. {"status": "running"}).
        config: Server configuration.
        security: Security manager.
    """
    args = ["ps", "--format", "json"]
    if all:
        args.append("-a")
    if filters:
        for key, val in filters.items():
            args.extend(["--filter", f"{key}={val}"])

    ok, stdout, stderr = await _run_docker(args, config)
    if not ok:
        return make_response(False, error=stderr)

    # Parse JSON lines output
    containers = []
    for line in stdout.strip().splitlines():
        if line.strip():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    security.audit.log("docker_ps", {"all": all}, True)
    return make_response(True, data={"containers": containers, "count": len(containers)})


async def docker_logs(
    container: str,
    tail: int = 100,
    since: str | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Get container logs.

    Args:
        container: Container name or ID.
        tail: Number of lines from the end (default: 100).
        since: Show logs since timestamp (e.g. "2024-01-01", "1h").
        config: Server configuration.
        security: Security manager.
    """
    args = ["logs", "--tail", str(tail)]
    if since:
        args.extend(["--since", since])
    args.append(container)

    ok, stdout, stderr = await _run_docker(args, config, timeout=15)
    # Docker logs writes to both stdout and stderr
    logs = stdout + stderr

    security.audit.log("docker_logs", {"container": container, "tail": tail}, ok)
    if not ok and not logs.strip():
        return make_response(False, error=stderr or "Failed to get container logs")
    return make_response(True, data={"container": container, "logs": logs})


async def docker_exec(
    container: str,
    command: str,
    user: str | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Execute a command inside a running container.

    Args:
        container: Container name or ID.
        command: Command to execute.
        user: User to run as (e.g. "root").
        config: Server configuration.
        security: Security manager.
    """
    ok, err = security.validate_command(command)
    if not ok:
        return make_response(False, error=err)

    args = ["exec"]
    if user:
        args.extend(["-u", user])
    args.extend([container, "sh", "-c", command])

    ok, stdout, stderr = await _run_docker(args, config, timeout=60)
    security.audit.log(
        "docker_exec", {"container": container, "command": command}, ok
    )
    return make_response(
        ok,
        data={"stdout": stdout, "stderr": stderr},
        error=stderr if not ok else None,
    )


async def docker_compose(
    action: str,
    project_dir: str,
    services: list[str] | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Docker Compose operations.

    Args:
        action: One of: up, down, restart, pull, logs, ps.
        project_dir: Directory containing docker-compose.yml.
        services: Optional list of specific services.
        config: Server configuration.
        security: Security manager.
    """
    valid_actions = {"up", "down", "restart", "pull", "logs", "ps"}
    if action not in valid_actions:
        return make_response(
            False, error=f"Invalid action: {action}. Must be one of {valid_actions}"
        )

    ok, err = security.validate_path(project_dir, write=False)
    if not ok:
        return make_response(False, error=err)

    args = ["compose", "-f", os.path.join(project_dir, "docker-compose.yml")]

    if action == "up":
        args.extend(["up", "-d"])
    elif action == "logs":
        args.extend(["logs", "--tail", "100"])
    else:
        args.append(action)

    if services:
        args.extend(services)

    ok, stdout, stderr = await _run_docker(args, config, timeout=120)
    security.audit.log(
        "docker_compose",
        {"action": action, "project_dir": project_dir},
        ok,
    )
    return make_response(
        ok,
        data={"stdout": stdout, "stderr": stderr},
        error=stderr if not ok else None,
    )


async def docker_stats(
    container: str | None = None,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Get CPU/Memory stats for containers.

    Args:
        container: Specific container name (or None for all).
        config: Server configuration.
        security: Security manager.
    """
    args = ["stats", "--no-stream", "--format", "json"]
    if container:
        args.append(container)

    ok, stdout, stderr = await _run_docker(args, config, timeout=15)
    if not ok:
        return make_response(False, error=stderr)

    stats = []
    for line in stdout.strip().splitlines():
        if line.strip():
            try:
                stats.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return make_response(True, data={"stats": stats})


async def docker_inspect(
    target: str,
    type: str = "container",
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Inspect Docker objects.

    Args:
        target: Name or ID of the object.
        type: One of: container, image, network, volume.
        config: Server configuration.
        security: Security manager.
    """
    valid_types = {"container", "image", "network", "volume"}
    if type not in valid_types:
        return make_response(False, error=f"Invalid type: {type}")

    args = [f"{type}", "inspect", target] if type != "container" else ["inspect", target]

    ok, stdout, stderr = await _run_docker(args, config, timeout=10)
    if not ok:
        return make_response(False, error=stderr)

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        data = stdout

    return make_response(True, data=data)


async def docker_images(
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """List Docker images.

    Args:
        config: Server configuration.
        security: Security manager.
    """
    args = ["images", "--format", "json"]
    ok, stdout, stderr = await _run_docker(args, config)
    if not ok:
        return make_response(False, error=stderr)

    images = []
    for line in stdout.strip().splitlines():
        if line.strip():
            try:
                images.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    security.audit.log("docker_images", {}, True)
    return make_response(True, data={"images": images, "count": len(images)})


async def docker_pull(
    image: str,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Pull a Docker image.

    Args:
        image: Image name with optional tag (e.g. "nginx:latest").
        config: Server configuration.
        security: Security manager.
    """
    ok, stdout, stderr = await _run_docker(
        ["pull", image], config, timeout=300
    )
    security.audit.log("docker_pull", {"image": image}, ok)
    return make_response(
        ok,
        data={"image": image, "output": stdout},
        error=stderr if not ok else None,
    )


async def docker_rmi(
    image: str, force: bool = False,
    *,
    config: ServerConfig,
    security: SecurityManager,
) -> dict:
    """Remove a Docker image.

    Args:
        image: Image name or ID.
        force: Force remove (default: False).
        config: Server configuration.
        security: Security manager.
    """
    args = ["rmi"]
    if force:
        args.append("-f")
    args.append(image)

    ok, stdout, stderr = await _run_docker(args, config)
    security.audit.log("docker_rmi", {"image": image, "force": force}, ok)
    return make_response(
        ok,
        data={"image": image, "output": stdout},
        error=stderr if not ok else None,
    )
