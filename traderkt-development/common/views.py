from rest_framework import permissions
from rest_framework import viewsets, status, views
from rest_framework.response import Response
from rest_framework.decorators import action
from generics.constants import DEFAULT_USER_TYPE
from users.serializers import UsersSerializer
from users.models import TraderKitUser, UserProfile, Group, Roles
from generics.Mailer import Mailer
import random
from rest_framework_jwt.settings import api_settings
from common.serializers import OtpRequestSerializer
from common.models import OtpRequests, ApiKeys
from rest_framework.decorators import api_view, permission_classes
import datetime

class OtpRequestViewSet(viewsets.ModelViewSet):
    permission_classes = (permissions.AllowAny,)
    serializer_class = OtpRequestSerializer
    queryset = OtpRequests.objects.all()

    def list(self, request, *args, **kwargs):
        queryset = self.queryset[:25]
        serializer = self.serializer_class(queryset, context={'request': request}, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        request.data['otp'] = random.randrange(1, 10 ** 6)
        message = 'Your Verification code is %s. valid 5 minutes only' % request.data['otp']
        OtpRequests.objects.filter(phone_number=request.data['phone_number']).update(status=True)
        data = Mailer.send_sms(message, request.data['phone_number'], request.data['otp'])
        if data['type'] == 'success':
            otp_instance = OtpRequests()
            otp_instance.__dict__.update(request.data)
            otp_instance.save()
            data = self.serializer_class(otp_instance, context={'request': request}).data
        return Response(data)

    @action(methods=['post'], detail=False, url_path='create-user')
    def create_user(self, request, *args, **kwargs):
        form_data = request.data
        form_data['username'] = form_data['email']
        form_data['email'] = form_data['email']
        user = TraderKitUser()
        user.__dict__.update(**form_data)
        user.save()
        user_role = Roles.objects.filter(alias='Users').first()
        permission_groups = Group.objects.filter(id=user_role.id)
        user.set_password(form_data['password'])
        user.save()
        user.groups.set(permission_groups)
        user.save()
        user_profile = UserProfile()
        user_profile.user = user
        user_profile.role_id = user_role.id
        user_profile.user_type = DEFAULT_USER_TYPE
        user_profile.created_by = TraderKitUser.objects.first()
        user_profile.mobile = form_data['mobile']
        user_profile.save()
        user_details = UsersSerializer(user, context={'request': request}).data
        # handle the users token's
        payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = payload_handler(user)
        token = encode_handler(payload)
        user_details['token'] = token
        return Response(user_details)

    @action(methods=['post'], detail=False, url_path='check-email-exist')
    def check_email_exist(self, request, **kwargs):
        form_data = request.data
        user = TraderKitUser.objects.filter(username=form_data['email']).first()
        return_data = dict()
        if user is not None:
            return_data['exist'] = True
            return Response(return_data, status=400)
        else:
            return_data['exist'] = False
            return Response(return_data)

    @action(methods=['post'], detail=False, url_path='verify-email')
    def verify_email(self, request, **kwargs):
        form_data = request.data
        user = TraderKitUser.objects.filter(username=form_data['email']).first()
        return_data = dict()
        if user is not None:
            return_data['exist'] = True
            return Response(return_data)
        else:
            return_data['exist'] = False
            return Response(return_data, status=400)

    @action(methods=['post'], detail=False, url_path='set-password')
    def set_password(self, request, **kwargs):
        form_data = request.data
        user = TraderKitUser.objects.filter(username=form_data['email']).first()
        user.set_password(form_data['password'])
        user.save()
        return Response(True)