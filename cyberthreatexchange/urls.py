"""
URL configuration for cyberthreatexchange project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from rest_framework import routers
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from cyberthreatexchange.server import views
import dogesec_commons.objects.views as arango_views


from django.http import JsonResponse

def handler404(*args, **kwargs):
    return JsonResponse(dict(code=404, message='non-existent page'), status=404)

def handler500(*args, **kwargs):
    return JsonResponse(dict(code=500, message='internal server error'), status=500)

API_VERSION = "v1"

router = routers.SimpleRouter(use_regex_path=False)
router.register("identities", views.IdentityView, "identity-view")
router.register("jobs", views.JobView, "job-view")
router.register("search", views.SearchView, "semantic-search-view")
router.register("search/values", views.ObjectValueSearchView, "object-value-search-view")
router.register("feeds", views.FeedView, "feed-view")
router.register("feeds/<feed_id>/objects", views.FeedObjectsView, "feed-objects-view")


urlpatterns = [
    # path(f'api/healthcheck/', views.health_check),
    path(f'api/{API_VERSION}/', include(router.urls)),
    path('admin/', admin.site.urls),
    # YOUR PATTERNS
    path('api/schema/', views.SchemaViewCached.as_view(), name='schema'),
    # Optional UI:
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
