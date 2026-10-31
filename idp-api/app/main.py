"""
Mini SSO FastAPI Main Application Entrypoint.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.api.routes_admin import router as admin_router
from app.api.routes_auth import router as auth_router
from app.api.routes_oidc import router as oidc_router
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.models import Client
from app.services.auth_service import get_or_create_jwt_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mini_sso")


def init_db_and_defaults():
    """Initializes tables, seeds demo client app, and generates RSA signing key."""
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        # Ensure active RSA signing key exists
        jwt_svc = get_or_create_jwt_service(db)
        logger.info(f"Initialized active RSA key with kid: {jwt_svc.kid}")

        # Seed default Demo Client if not present
        demo_client_id = "demo-client-app"
        existing = db.scalars(select(Client).where(Client.client_id == demo_client_id)).first()
        if not existing:
            demo_client = Client(
                client_id=demo_client_id,
                name="Mini SSO Demo Application",
                redirect_uris=[
                    "http://localhost:5174/callback",
                    "http://localhost:3001/callback",
                    "http://127.0.0.1:5174/callback",
                    "http://127.0.0.1:3001/callback",
                ],
                allowed_cidrs=None,
            )
            db.add(demo_client)
            db.commit()
            logger.info("Seeded default demo client application")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_and_defaults()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="OpenID Connect Login Service with Argon2id, RFC 6238 TOTP MFA, PKCE S256, and JWKS",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration allowing credentials for cookies
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(oidc_router)
app.include_router(auth_router)
app.include_router(admin_router)


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "app": settings.APP_NAME, "environment": settings.ENVIRONMENT}
