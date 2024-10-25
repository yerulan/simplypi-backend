from django.contrib.auth.models import Group, User
from rest_framework import permissions, viewsets, generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
import logging
import stripe
import uuid
import json
from datetime import timedelta, datetime

from .models import PendingRegistration, ChatSession, ChatMessage
from quickstart.serializers import GroupSerializer, UserSerializer
from .gpt import generate_gpt_response

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
        domain_url = "http://simplypi.io"
        lookupKey = request.data.get('lookupKey')
        recurringLookupKey = request.data.get('recurringLookupKey')
        trialPeriodDays = request.data.get('trialPeriodDays')
        query_params = request.data.get('queryParams')
        try:
            prices = stripe.Price.list(
                lookup_keys=[lookupKey, recurringLookupKey] if recurringLookupKey else [lookupKey],
                expand=['data.product']
            )

            success_url = f"{domain_url}/success-page?success=true&session_id={{CHECKOUT_SESSION_ID}}"
            cancel_url = f"{domain_url}/selling-page"

            if query_params:
                success_url = f"{success_url}&{query_params}"
                cancel_url = f"{cancel_url}?{query_params}"

            if recurringLookupKey is None:
                checkout_session = stripe.checkout.Session.create(
                    line_items=[
                        {
                            'price': prices.data[0].id,
                            'quantity': 1,
                        },
                    ],
                    mode='subscription',
                    ui_mode='embedded',
                    redirect_on_completion='never',
                )
                return Response({'id': checkout_session.id, 'url': checkout_session.url, 'clientSecret': checkout_session.client_secret})

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
                ui_mode='embedded',
                redirect_on_completion='never',
            )
            return Response({'id': checkout_session.id, 'url': checkout_session.url, 'clientSecret': checkout_session.client_secret})
        except Exception as e:
            logger.error(f"Error creating checkout session: {e}")
            return Response({'error': str(e)})


class CreateCustomerPortalView(APIView):
    def post(self, request, *args, **kwargs):
        stripe.api_key = settings.STRIPE_SECRET_KEY
        checkout_session_id = request.data.get('session_id')
        checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)

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
            logger.error(f"Invalid payload: {e}")
            return Response({'error': 'Invalid payload'}, status=400)
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid signature: {e}")
            return Response({'error': 'Invalid signature'}, status=400)
        except Exception as e:
            logger.error(f"Unhandled error: {e}")
            return Response({'error': 'Unhandled error'}, status=500)

        try:
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                logger.info(f"Session object: {session}")
                customer_email = session.get('customer_details', {}).get('email')
                first_name = session.get('customer_details', {}).get('name')
                stripe_customer_id = session.get('customer')

                if customer_email and stripe_customer_id:
                    token = str(uuid.uuid4())
                    PendingRegistration.objects.create(
                        first_name=first_name,
                        email=customer_email,
                        token=token,
                        stripe_customer_id=stripe_customer_id
                    )
                    mail_subject = 'Complete your registration'
                    message = render_to_string('simplypi/registration_complete_email.html', {
                        'domain': "https://www.simplypi.io",
                        'token': token,
                    })
                    try:
                        email = EmailMessage(
                            mail_subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [customer_email]
                        )
                        email.content_subtype = "html"
                        email.send()
                        logger.info('Registration email sent successfully!')
                    except Exception as e:
                        logger.error(f"Failed to send registration email: {e}")

                    logger.info(f'Payment succeeded and email sent to {customer_email}!')
                else:
                    logger.warning('Customer email or Stripe customer ID is missing.')
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


class CompleteRegistrationView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        token = request.data.get('token')

        try:
            pending_registration = PendingRegistration.objects.get(email=email, token=token, is_active=False)
        except PendingRegistration.DoesNotExist:
            return Response({"error": "Invalid token or email."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=email, email=email, password=password)
        user.is_active = True
        user.stripe_customer_id = pending_registration.stripe_customer_id
        user.save()

        pending_registration.is_active = True
        pending_registration.save()

        return Response({"message": "Registration complete."}, status=status.HTTP_201_CREATED)


class SubscriptionStatusView(APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            stripe_customer_id = user.stripe_customer_id
            subscriptions = stripe.Subscription.list(customer=stripe_customer_id)

            active_subscription = any(
                subscription.status == 'active' or subscription.status == 'trialing' for subscription in subscriptions.data
            )

            if active_subscription:
                return Response({"subscription_status": "active"}, status=status.HTTP_200_OK)
            else:
                return Response({"subscription_status": "inactive"}, status=status.HTTP_200_OK)

        except PendingRegistration.DoesNotExist:
            return Response({"error": "User does not have a linked Stripe customer ID."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StartChatSessionView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        session = ChatSession.objects.create(user=user)
        return Response({'session_id': session.id})


class DeactivateChatSessionsView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        sessions = ChatSession.objects.filter(user=user)
        sessions.update(is_active=False)
        return Response({'message': 'All chat sessions have been deactivated.'}, status=status.HTTP_200_OK)


class SendMessageView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.user
        session_id = request.data.get('session_id')
        message = request.data.get('message')

        try:
            session = ChatSession.objects.get(id=session_id, user=user)
            ChatMessage.objects.create(session=session, sender='user', message=message)

            user_messages = ChatMessage.objects.filter(session=session, sender='user').order_by('timestamp')
            messages = [msg.message for msg in user_messages]
            gpt_response = generate_gpt_response(messages)
            ChatMessage.objects.create(session=session, sender='gpt', message=gpt_response)

            return Response({'response': gpt_response})
        except ChatSession.DoesNotExist:
            return Response({'error': 'Chat session not found.'}, status=status.HTTP_404_NOT_FOUND)


class ChatHistoryView(APIView):
    def get(self, request, session_id=None, *args, **kwargs):
        user = request.user

        if session_id:
            try:
                session = ChatSession.objects.get(id=session_id, user=user, is_active=True)
                messages = session.messages.all().order_by('timestamp')
                chat_history = [
                    {'sender': msg.sender, 'message': msg.message, 'timestamp': msg.timestamp}
                    for msg in messages
                ]
                return Response({'chat_history': chat_history})
            except ChatSession.DoesNotExist:
                return Response({'error': 'Chat session not found.'}, status=status.HTTP_404_NOT_FOUND)
        else:
            now = datetime.now()
            today = now.date()
            last_week = now - timedelta(weeks=1)
            last_month = now - timedelta(weeks=4)

            sessions_today = ChatSession.objects.filter(user=user, is_active=True, created_at__date=today).order_by('-created_at')
            sessions_last_week = ChatSession.objects.filter(user=user, is_active=True, created_at__gte=last_week, created_at__lt=today).order_by('-created_at')
            sessions_last_month = ChatSession.objects.filter(user=user, is_active=True, created_at__gte=last_month, created_at__lt=last_week).order_by('-created_at')

            sessions_data = {
                'today': [
                    {'session_id': session.id, 'title': session.title, 'created_at': session.created_at}
                    for session in sessions_today
                ],
                'last_week': [
                    {'session_id': session.id, 'title': session.title, 'created_at': session.created_at}
                    for session in sessions_last_week
                ],
                'last_month': [
                    {'session_id': session.id, 'title': session.title, 'created_at': session.created_at}
                    for session in sessions_last_month
                ],
            }
            return Response({'chat_sessions': sessions_data})
