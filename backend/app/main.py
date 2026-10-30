"""
OpenSOC Forge - Central Management API Service.
Modular, version-resilient SIEM/SOC Management Plane.
"""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.v1.api import api_router
from backend.app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="OpenSOC Forge: Modular, Version-Resilient SIEM and SOC Operations Platform",
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
)

# CORS middleware for Web Console UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforces essential browser defense headers (OWASP guidelines)."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' data: https:; img-src 'self' data: https:;"
    return response


# Include API v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Mount Web Console at /console
import os
from starlette.staticfiles import StaticFiles
base_repo_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
frontend_dir = os.path.join(base_repo_dir, "frontend")
if os.path.exists(frontend_dir):
    app.mount("/console", StaticFiles(directory=frontend_dir, html=True), name="console")

downloads_dir = os.path.join(base_repo_dir, "downloads")
os.makedirs(downloads_dir, exist_ok=True)
app.mount("/downloads", StaticFiles(directory=downloads_dir), name="downloads")


@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "docs_url": "/api/v1/docs",
        "management_plane": "ACTIVE",
    }


@app.on_event("startup")
def on_startup():
    try:
        from backend.app.services.proxy_manager import init_proxy_on_startup
        init_proxy_on_startup()
    except Exception as e:
        print(f"Failed to init proxy: {e}")

    try:
        from backend.app.services.ioc_storage import init_ioc_database
        init_ioc_database()
    except Exception as e:
        print(f"Failed to init IOC database: {e}")

    try:
        from backend.app.services.host_storage import init_host_database
        init_host_database()
    except Exception as e:
        print(f"Failed to init Host database: {e}")

    try:
        from backend.app.services.github_sync import start_github_sync_scheduler
        start_github_sync_scheduler()
    except Exception as e:
        print(f"Failed to start GitHub sync scheduler: {e}")

    try:
        from backend.app.services.correlation_engine.service import init_correlation_engine_on_startup
        init_correlation_engine_on_startup()
    except Exception as e:
        print(f"Failed to init correlation engine: {e}")

    try:
        from backend.app.services.netwitness_storage import init_storage
        init_storage()
        from backend.app.services.netwitness_siem import start_netwitness_daemon
        start_netwitness_daemon()
    except Exception as e:
        print(f"Failed to init NetWitness 30-day telemetry storage: {e}")


@app.on_event("shutdown")
def on_shutdown():
    try:
        from backend.app.services.correlation_engine.service import shutdown_correlation_engine
        shutdown_correlation_engine()
    except Exception as e:
        print(f"Failed to shutdown correlation engine: {e}")

    try:
        from backend.app.services.netwitness_siem import stop_netwitness_daemon
        stop_netwitness_daemon()
    except Exception as e:
        print(f"Failed to stop NetWitness daemon: {e}")


from fastapi.responses import RedirectResponse

@app.get("/docs", include_in_schema=False)
def redirect_docs():
    return RedirectResponse(url="/api/v1/docs")


@app.get("/redoc", include_in_schema=False)
def redirect_redoc():
    return RedirectResponse(url="/api/v1/redoc")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
