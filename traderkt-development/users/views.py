import datetime
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import Group
from django.db.models import Q
from django.utils.decorators import method_decorator
from rest_framework import permissions
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
#from rest_framework_jwt.settings import api_settings
from generics.Mailer import Mailer
from generics.defaults import AppDefaults
from users.models import TraderKitUser, PasswordResetTokens, Roles
from users.serializers import UsersSerializer, GroupSerializer


def jwt_response_payload_handler(token, user=None, request=None):
    """ Modifying jwt login response details """
    user_details = UsersSerializer(user, context={'request': request}).data

    """ Fetching assigned accesses for the use """
    user_details['accesses'] = list()

    if user.is_superuser:
        user_details['accesses'] = AppDefaults.get_predefined_role_access_specifiers('Admin')
    else:
        access_joined = user.groups.all().values_list('details__accesses', flat=True)
        for string in access_joined:
            if string is not None:
                user_details['accesses'] += string.split(',')
        user_details['accesses'] = list(set(user_details['accesses']))

    user_details['accesses'] = sorted(user_details['accesses'])

    return {
        'token': token,
        'user': user_details
    }


@method_decorator(permission_required('users.view_tradinguser', raise_exception=True), name='list')
@method_decorator(permission_required('users.view_tradinguser', raise_exception=True), name='retrieve')
@method_decorator(permission_required('users.add_tradinguser', raise_exception=True), name='create')
@method_decorator(permission_required('users.change_tradinguser', raise_exception=True), name='update')
@method_decorator(permission_required('users.change_tradinguser', raise_exception=True), name='partial_update')
@method_decorator(permission_required('users.delete_tradinguser', raise_exception=True), name='destroy')
class UsersViewSet(viewsets.ModelViewSet):
    permission_classes = (permissions.IsAuthenticated,)
    queryset = TraderKitUser.objects.all()
    serializer_class = UsersSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            query_set = TraderKitUser.objects.all()
        else:
            query_set = self.queryset.filter(profile__created_by=user)
        return query_set

    def destroy(self, request, *args, **kwargs):
        self.get_queryset().filter(id=kwargs['pk']).update(is_active=0)
        return Response(True)

    @action(methods=['post'], detail=False, url_path='check-username')
    def check_user_list(self, request, *args, **kwargs):
        user_name = request.data['username']
        queryset = TraderKitUser.objects.filter(username=user_name)
        check_exist = len(queryset)
        return Response(check_exist)

    @method_decorator(permission_required('users.add_smarthomeuser', raise_exception=True), name='create')
    def create(self, request, *args, **kwargs):
        request.data['user_id'] = request.user.id
        password = request.data['password']

        user = super(self.__class__, self).create(request, *args, **kwargs)
        user_id = user.data['id']

        u = TraderKitUser.objects.get(pk=user_id)
        u.set_password(password)
        u.save()
        serializer = self.serializer_class(u, context={'request': request})
        data = serializer.data

        try:
            from django.conf import settings
            logo_path = settings.STATIC_URL + 'images/logo-sample.png'
            details = {
                'user_detail': data,
                'password': password,
                'logo_path': logo_path
            }
            Mailer.send_mail(
                subject='BEE: User Creation',
                recipients=[data['email']],
                template_name='user_welcome.html',
                template_data=details
            )

        except Exception as e:
            print(e)
            pass
        return Response(True)

    def update(self, request, *args, **kwargs):
        user_id = kwargs['pk']
        password = request.data['password']
        request.data.pop('password', None)
        super(self.__class__, self).update(request, *args, **kwargs)
        u = TraderKitUser.objects.get(pk=user_id)
        if u.password != password:
            u.set_password(password)
            u.save()
        return Response(True)

    @action(methods=['post'], detail=False, url_path='change-password')
    def change_password(self, request):
        user = self.request.user
        old_password = request.data['old_password']
        from django.contrib.auth import authenticate
        credentials = {
            'email': user.email,
            'password': old_password
        }
        user = authenticate(**credentials)
        if user:
            user.set_password(request.data['password'])
            user.save()

            return Response({'msg': "Your Password changed"})
        else:
            return Response({'msg': "Your old password was entered incorrectly"}, status=400)

    def list(self, request, *args, **kwargs):
        query_params = request.query_params.dict()
        offset = int(query_params.pop('offset', 0))
        end = int(query_params.pop('limit', 5))
        username_list = [request.user.username, 'AnonymousUser']
        queryset = self.get_queryset().filter(is_active=1).exclude(username__in=username_list)
        order_by = query_params.pop('order_by', None)
        search_text = query_params.pop('searchText', None)
        query_set = queryset

        if search_text is not None:
            query_set = query_set.filter(
                Q(first_name__icontains=search_text) |
                Q(email__icontains=search_text) |
                Q(last_name__icontains=search_text))
        if order_by is not None:
            if order_by == 'full_name' or order_by == '-full_name':
                order_by = order_by.replace('full_name', 'first_name')
            query_set = query_set.order_by(order_by)
        total_records = query_set.filter(is_active=1).count()
        query_set = query_set[offset:end]
        serializer = UsersSerializer(query_set, many=True, context={'request': request})
        return Response({'records': serializer.data, 'totalRecords': total_records})


class GroupsViewSet(viewsets.ModelViewSet):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = GroupSerializer

    def get_queryset(self):
        user = self.request.user
        queryset = Group.objects.none()
        if user.is_superuser:
            queryset = Group.objects.filter((Q(details__created_by=user) | Q(details__created_by=None))) \
                .exclude(details__alias__isnull=True)
        else:
            queryset = Group.objects.filter(details__created_by=user).exclude(details__alias__isnull=True)

        return queryset.order_by('details__alias')

    @action(methods=['get'], detail=True, url_path='delete_role')
    def delete_role_check(self, request, **kwargs):
        role_id = kwargs["pk"]
        role_name = Group.objects.get(id=role_id)
        user_list = role_name.user_set.exclude(is_active=0).all()
        user = user_list.exists()
        predefined = AppDefaults.get_predefined_roles()
        predefined_value = role_name.name in predefined.values()
        if predefined_value:
            return Response(False)
        elif user:
            return Response("exists")
        else:
            return Response(True)

    def destroy(self, request, *args, **kwargs):
        id = kwargs["pk"]
        query = self.get_queryset().get(id=id)
        query.details.delete()
        queryset = self.get_queryset()
        serializer = GroupSerializer(queryset, many=True, context={'request': request})
        return Response(serializer.data)


class PasswordResetVerify(APIView):
    """ Verifies password reset token """
    permission_classes = (permissions.AllowAny,)
    serializer_class = VerifyJSONWebTokenSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            if PasswordResetTokens.objects.filter(token=data['token']).exists():
                return Response(data['token'])
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirm(APIView):
    """ Changes user password """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data

        """ Updating password """
        user.set_password(data['password'])
        user.save()
        """ Removing token from password reset session after changing password """
        session = PasswordResetTokens.objects.filter(user=user)
        session.delete()

        Mailer.send_mail(
            subject='REDINGTON: Password changed',
            recipients=[user.email],
            template_name='password_changed.html',
            template_data={
                'user': user.__dict__
            }
        )

        serializer = UsersSerializer(user, context={'request': request})
        return Response(serializer.data)


api_password_reset_verify = PasswordResetVerify.as_view()
api_password_reset_confirm = PasswordResetConfirm.as_view()
