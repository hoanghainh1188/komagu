"""API inventory and shadow/zombie API detection package."""
from operate.inventory.api_inventory import (
    diff_api_inventory,
    load_code_routes,
    load_openapi_spec,
    load_traffic_log,
    normalize_path,
    normalize_route_key,
    render_inventory_html,
    render_inventory_md,
)

__all__ = [
    "diff_api_inventory",
    "load_code_routes",
    "load_openapi_spec",
    "load_traffic_log",
    "normalize_path",
    "normalize_route_key",
    "render_inventory_html",
    "render_inventory_md",
]
