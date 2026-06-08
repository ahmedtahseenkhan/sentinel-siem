"""
Cloud connector manager — schedules AWS, Azure, and GCP syncs via APScheduler.
Initialised alongside the report scheduler in app.py startup.
"""
import logging
import os

logger = logging.getLogger(__name__)

_scheduler = None


def _make_os_client():
    """Build a minimal OpenSearch client using the existing OPENSEARCH_URL config."""
    from opensearchpy import OpenSearch
    url  = os.getenv("OPENSEARCH_URL", "http://opensearch-node1:9200")
    user = os.getenv("OPENSEARCH_USER", "admin")
    pwd  = os.getenv("OPENSEARCH_PASSWORD", "admin")
    return OpenSearch(
        hosts=[url],
        http_auth=(user, pwd),
        use_ssl=url.startswith("https"),
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )


def _run_aws():
    try:
        from cloud_connectors.aws import run_sync
        run_sync(_make_os_client())
    except Exception as e:
        logger.error("cloud manager: aws sync error: %s", e)


def _run_azure():
    try:
        from cloud_connectors.azure import run_sync
        run_sync(_make_os_client())
    except Exception as e:
        logger.error("cloud manager: azure sync error: %s", e)


def _run_gcp():
    try:
        from cloud_connectors.gcp import run_sync
        run_sync(_make_os_client())
    except Exception as e:
        logger.error("cloud manager: gcp sync error: %s", e)


def init_cloud_connectors(scheduler):
    """
    Register cloud connector jobs with the given APScheduler instance.
    Each connector runs every CLOUD_SYNC_INTERVAL_MINUTES (default 15).
    """
    global _scheduler
    _scheduler = scheduler
    interval = int(os.getenv("CLOUD_SYNC_INTERVAL_MINUTES", "15"))

    try:
        from cloud_connectors.aws   import is_configured as aws_ok
        from cloud_connectors.azure import is_configured as az_ok
        from cloud_connectors.gcp   import is_configured as gcp_ok

        if aws_ok():
            scheduler.add_job(
                _run_aws,
                "interval",
                minutes=interval,
                id="cloud_aws",
                replace_existing=True,
            )
            logger.info("cloud manager: AWS connector scheduled every %dm", interval)

        if az_ok():
            scheduler.add_job(
                _run_azure,
                "interval",
                minutes=interval,
                id="cloud_azure",
                replace_existing=True,
            )
            logger.info("cloud manager: Azure connector scheduled every %dm", interval)

        if gcp_ok():
            scheduler.add_job(
                _run_gcp,
                "interval",
                minutes=interval,
                id="cloud_gcp",
                replace_existing=True,
            )
            logger.info("cloud manager: GCP connector scheduled every %dm", interval)

    except Exception as e:
        logger.warning("cloud manager: init failed: %s", e)


def get_all_statuses() -> list:
    """Return current status for all three providers."""
    from cloud_connectors.aws   import get_status as aws_status
    from cloud_connectors.azure import get_status as az_status
    from cloud_connectors.gcp   import get_status as gcp_status
    return [aws_status(), az_status(), gcp_status()]


def trigger_sync(provider: str) -> dict:
    """Trigger an immediate sync for the given provider."""
    os_client = _make_os_client()
    if provider == "aws":
        from cloud_connectors.aws import run_sync
        count = run_sync(os_client)
    elif provider == "azure":
        from cloud_connectors.azure import run_sync
        count = run_sync(os_client)
    elif provider == "gcp":
        from cloud_connectors.gcp import run_sync
        count = run_sync(os_client)
    else:
        return {"error": f"unknown provider: {provider}"}
    return {"provider": provider, "events_indexed": count, "message": "sync complete"}
