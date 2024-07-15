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
        request_data = request.body

        if webhook_secret:
            # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
            signature = request.headers.get('stripe-signature')
            try:
                event = stripe.Webhook.construct_event(
                    payload=request.data, sig_header=signature, secret=webhook_secret)
                data = event['data']
            except Exception as e:
                return e
            # Get the type of webhook event sent - used to check the status of PaymentIntents.
            event_type = event['type']
        else:
            data = request_data['data']
            event_type = request_data['type']
        data_object = data['object']

        print('event ' + event_type)

        if event_type == 'checkout.session.completed':
            print('🔔 Payment succeeded!')
        elif event_type == 'customer.subscription.trial_will_end':
            print('Subscription trial will end')
        elif event_type == 'customer.subscription.created':
            print('Subscription created %s', event.id)
        elif event_type == 'customer.subscription.updated':
            print('Subscription created %s', event.id)
        elif event_type == 'customer.subscription.deleted':
            # handle subscription canceled automatically based
            # upon your subscription settings. Or if the user cancels it.
            print('Subscription canceled: %s', event.id)
        elif event_type == 'entitlements.active_entitlement_summary.updated':
            # handle active entitlement summary updated
            print('Active entitlement summary updated: %s', event.id)

        return Response({'status': 'success'})
