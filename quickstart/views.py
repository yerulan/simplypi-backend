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
import time
from facebook_business.adobjects.serverside.content import Content
from facebook_business.adobjects.serverside.custom_data import CustomData 
from facebook_business.adobjects.serverside.delivery_category import DeliveryCategory
from facebook_business.adobjects.serverside.event import Event
from facebook_business.adobjects.serverside.event_request import EventRequest
from facebook_business.adobjects.serverside.gender import Gender
from facebook_business.adobjects.serverside.user_data import UserData


logger = logging.getLogger(__name__)


pixel_id = settings.PIXEL_ID

webhook_secret = settings.STRIPE_WEBHOOK_SECRET

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
        domain_url = "https://simplypi.io"
        lookupKey = request.data.get('lookupKey')
        recurringLookupKey = request.data.get('recurringLookupKey')
        trialPeriodDays = request.data.get('trialPeriodDays')
        try:
            prices = stripe.Price.list(
                lookup_keys= [lookupKey, recurringLookupKey] if recurringLookupKey != None else [lookupKey],
                expand=['data.product']
            )

            if recurringLookupKey == None:
                checkout_session = stripe.checkout.Session.create(
                    line_items=[
                        {
                            'price': prices.data[0].id,
                            'quantity': 1,
                        },
                    ],
                    mode='subscription',
                    success_url=domain_url +
                    '/success-page?success=true&session_id={CHECKOUT_SESSION_ID}',
                    cancel_url=domain_url + '/success-page?canceled=true',
                )
                return Response({'id': checkout_session.id, 'url': checkout_session.url})
            
            one_time_price = None
            subscription_price = None

            for price in prices.data:
                if price.lookup_key == lookupKey:
                    one_time_price = price
                elif price.lookup_key == recurringLookupKey:
                    subscription_price = price

            checkout_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        'price': one_time_price.id,
                        'quantity': 1,
                    },
                    {
                        'price': subscription_price.id,
                        'quantity': 1,
                    },
                ],
                mode='subscription',
                subscription_data={
                    'trial_period_days': trialPeriodDays,
                },
                success_url=domain_url +
                '/success-page?success=true&session_id={CHECKOUT_SESSION_ID}',
                cancel_url=domain_url + '/success-page?canceled=true',
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
        print("WEBHOOK SECRET IS ", webhook_secret)
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
                # Send pixel event
                user_data_0 = UserData( emails=["7b17fb0bd173f625b58636fb796407c22b3d16fc78302d79f0fd30c2fc2fc068"], phones=[] )
                custom_data_0 = CustomData( value=142.52, currency="USD" )
                event_0 = Event( event_name="Purchase", event_time=1721670188, user_data=user_data_0, custom_data=custom_data_0, action_source="website" ) 
                events = [event_0]
                event_request = EventRequest( events=events, pixel_id=pixel_id )
                event_response = event_request.execute()
                print("EVENT RESPONSE: ", event_response)



                session = event['data']['object']
                logger.info(f"Session object: {session}")
                customer_email = session.get('customer_details', {}).get('email')
                first_name = session.get('customer_details', {}).get('name')
                stripe_customer_id = session.get('customer')

                if customer_email and stripe_customer_id:
                    user, created = User.objects.get_or_create(
                        username=customer_email, 
                        email=customer_email,
                        first_name=first_name,
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
                        try:
                            send_mail(
                                mail_subject,
                                message,
                                settings.EMAIL_HOST_USER,
                                [customer_email]
                            )
                            logger.info('🔔 Registration email sent successfully!')
                        except Exception as e:
                            logger.error(f"Failed to send registration email: {e}")


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
