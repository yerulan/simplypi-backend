from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets, generics

from quickstart.serializers import GroupSerializer, UserSerializer

import stripe
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
import logging
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
import logging


logger = logging.getLogger(__name__)


webhook_secret = 'whsec_hc9ddzDdSHaxwkN4rt2ubfuOe7lFJUdj'

stripe.api_key = settings.STRIPE_SECRET_KEY


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
        stripe.api_key = settings.STRIPE_SECRET_KEY
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
        stripe.api_key = settings.STRIPE_SECRET_KEY
        payload = request.body.decode('utf-8')
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        try:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=webhook_secret
            )
        except ValueError as e:
            # Invalid payload
            logger.error(f"Invalid payload: {e}")
            return Response({'error': 'Invalid payload'}, status=400)
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            logger.error(f"Invalid signature: {e}")
            return Response({'error': 'Invalid signature'}, status=400)
        except Exception as e:
            # Generic error handler
            logger.error(f"Unhandled error: {e}")
            return Response({'error': 'Unhandled error'}, status=500)

        try:
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                customer_email = session.get('customer_email')
                stripe_customer_id = session.get('customer')

                if customer_email and stripe_customer_id:
                    user, created = User.objects.get_or_create(
                        username=customer_email, 
                        email=customer_email,
                        defaults={'is_active': False}  # Set the user as inactive until they complete registration
                    )
                    if created:
                        user.profile.stripe_customer_id = stripe_customer_id
                        user.save()

                        # Send email to complete registration
                        current_site = get_current_site(request)
                        mail_subject = 'Complete your registration'
                        message = render_to_string('registration_complete_email.html', {
                            'user': user,
                            'domain': current_site.domain,
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                            'token': default_token_generator.make_token(user),
                        })
                        send_mail(
                            mail_subject, 
                            message, 
                            settings.EMAIL_HOST_USER, 
                            [customer_email]
                        )

                    logger.info('🔔 Payment succeeded and user created!')
                else:
                    logger.warning('Customer email or Stripe customer ID is missing.')
                # Handle successful payment intent here
            elif event['type'] == 'customer.subscription.trial_will_end':
                logger.info('Subscription trial will end')
            elif event['type'] == 'customer.subscription.created':
                logger.info(f'Subscription created: {event.id}')
            elif event['type'] == 'customer.subscription.updated':
                logger.info(f'Subscription updated: {event.id}')
            elif event['type'] == 'customer.subscription.deleted':
                logger.info(f'Subscription canceled: {event.id}')
            elif event['type'] == 'entitlements.active_entitlement_summary.updated':
                logger.info(f'Active entitlement summary updated: {event.id}')
        except Exception as e:
            logger.error(f"Error handling event: {e}")
            return Response({'error': 'Error handling event'}, status=500)

        return Response({'status': 'success'}, status=200)
