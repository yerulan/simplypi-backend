from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets, generics

from quickstart.serializers import GroupSerializer, UserSerializer

import stripe
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all().order_by('name')
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAdminUser]


class CreateCheckoutSessionView(APIView):
    def post(self, request, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        domain_url = f"{request.scheme}://{request.get_host()}/"
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[
                    {
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': 'T-shirt',
                            },
                            'unit_amount': 2000,
                        },
                        'quantity': 1,
                    },
                ],
                mode='payment',
                success_url=domain_url + 'success/',
                cancel_url=domain_url + 'cancel/',
            )
            return Response({'id': checkout_session.id})
        except Exception as e:
            return Response({'error': str(e)})
