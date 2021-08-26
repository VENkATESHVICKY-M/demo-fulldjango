from rest_framework import routers
from users.views import UsersViewSet, GroupsViewSet
from common.views import OtpRequestViewSet
# Defining Router
traderkit_app_router = routers.DefaultRouter()
# users app related view set url config
traderkit_app_router.register(r'common', OtpRequestViewSet)
traderkit_app_router.register(r'users', UsersViewSet)
traderkit_app_router.register(r'roles', GroupsViewSet, 'group')