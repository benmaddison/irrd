from starlette.routing import Route

from .http_endpoints import (
    index, rpsl_detail, rpsl_update, user_detail, permission_add, permission_delete,
    mntner_migrate_initiate, mntner_migrate_complete,
)
from .auth import login, logout

UI_ROUTES = [
    Route("/", index, name="index"),
    Route(
        "/rpsl/update/{source}/{object_class}/{rpsl_pk:path}",
        rpsl_update,
        name="rpsl_update",
        methods=["GET", "POST"],
    ),
    Route("/rpsl/update/", rpsl_update, name="rpsl_update", methods=["GET", "POST"]),
    Route(
        "/rpsl/{source}/{object_class}/{rpsl_pk:path}", rpsl_detail, name="rpsl_detail"
    ),
    Route(
        "/migrate-mntner/",
        mntner_migrate_initiate,
        name="mntner_migrate_initiate",
        methods=["GET", "POST"],
    ),
    Route(
        "/migrate-mntner/complete/{pk:uuid}/{token}",
        mntner_migrate_complete,
        name="mntner_migrate_complete",
        methods=["GET", "POST"],
    ),
    Route("/user", user_detail, name="user_detail"),
    Route(
        "/permission/add/{mntner:uuid}",
        permission_add,
        name="permission_add",
        methods=["GET", "POST"],
    ),
    Route(
        "/permission/delete/{permission:uuid}",
        permission_delete,
        name="permission_delete",
        methods=["GET", "POST"],
    ),
    Route("/login/", login, name="login", methods=["GET", "POST"]),
    Route("/logout/", logout, name="logout"),
]
