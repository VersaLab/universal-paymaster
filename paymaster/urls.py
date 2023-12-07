from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path
from paymaster import paymaster

urlpatterns = [
    path("legacy_admin/", admin.site.urls),
    path("paymaster", paymaster.jsonrpc),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
