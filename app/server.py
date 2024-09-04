from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from lib.crud import get_all_roles
from lib.helper import RoleCache

from .admin_api import admin_app
from .auth_api import auth_app
from .user_api import user_app

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/auth", auth_app)
app.mount("/user", user_app)
app.mount("/admin", admin_app)


@app.on_event("startup")
async def on_startup():
    roles = await get_all_roles()
    role_cache = RoleCache()
    role_cache.update_roles([{"role_id": role.id, "role_name": role.name} for role in roles])
