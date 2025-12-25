import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict

from .routes import setup_routes, lifespan


class HealthResponse(BaseModel):
    status: str
    version: str
    features: list


class CookieResponse(BaseModel):
    cookies: Dict[str, str]
    user_agent: str


def create_app(enable_proxy: bool = True, proxy_port: int = 8080) -> FastAPI:
    """Create and configure the FastAPI application."""

    # Create lifespan with proxy configuration
    from functools import partial
    app_lifespan = partial(lifespan, enable_proxy=enable_proxy, proxy_port=proxy_port)

    app = FastAPI(
        title="Cloudflare Bypasser",
        description="Firefox-only Camoufox-based Cloudflare bypasser with request mirroring and HTTP proxy",
        version="2.0.0",
        lifespan=app_lifespan
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s - %(name)s - %(message)s',
        datefmt='%H:%M:%S'
    )

    # Setup routes
    setup_routes(app)

    return app