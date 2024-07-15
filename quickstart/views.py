from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets, generics

from quickstart.serializers import GroupSerializer, UserSerializer

import stripe
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings


webhook_secret = 'whsec_6b5d31cb74c3bd00feaeef7b901dffa4c535265f0de8778a7f710da1a8f01748'


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
        referer = request.META.get('HTTP_REFERER')
        domain_url = referer if referer else f"{request.scheme}://{request.get_host()}/"
        lookupKey = request.data.get('lookupKey')
        try:
            prices = stripe.Price.list(
                lookup_keys=[lookupKey],
                expand=['data.product']
            )
            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        'price': prices.data[0].id,
                        'quantity': 1,
                    },
                ],
                mode='subscription',
                success_url=domain_url +
                '?success=true&session_id={CHECKOUT_SESSION_ID}',
                cancel_url=domain_url + '?canceled=true',
            )
            return Response({'id': checkout_session.id, 'url': checkout_session.url})
        except Exception as e:
            print(e)
            return Response({'error': str(e)})

class CreateCustomerPortalView(APIView):
    def post(self, request, *args, **kwargs):
        checkout_session_id = request.form.get('session_id')
        checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)

        # This is the URL to which the customer will be redirected after they are
        # done managing their billing with the portal.
        referer = request.META.get('HTTP_REFERER')
        domain_url = referer if referer else f"{request.scheme}://{request.get_host()}/"

        portalSession = stripe.billing_portal.Session.create(
            customer=checkout_session.customer,
            return_url=domain_url,
        )
        return Response({'id': portalSession.id, 'url': portalSession.url})

class WebhookEndpointView(APIView):
    def post(self, request, *args, **kwargs):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        try:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=webhook_secret
            )
        except ValueError:
            # Invalid payload
            return Response(status=400)
        except stripe.error.SignatureVerificationError:
            # Invalid signature
            return Response(status=400)

        # Handle the event
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            print('🔔 Payment succeeded!')
            # Handle successful payment intent here

        # Handle other event types
        elif event['type'] == 'customer.subscription.trial_will_end':
            print('Subscription trial will end')
        elif event['type'] == 'customer.subscription.created':
            print('Subscription created %s' % event.id)
        elif event['type'] == 'customer.subscription.updated':
            print('Subscription updated %s' % event.id)
        elif event['type'] == 'customer.subscription.deleted':
            print('Subscription canceled: %s' % event.id)
        elif event['type'] == 'entitlements.active_entitlement_summary.updated':
            print('Active entitlement summary updated: %s' % event.id)

        return Response({'status': 'success'})
