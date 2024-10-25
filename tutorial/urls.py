"""
URL configuration for tutorial project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
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
from django.urls import include, path
from rest_framework import routers
from quickstart import views
from django.views.generic import TemplateView

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('', include(router.urls)),
    path('api/auth/', include('dj_rest_auth.urls')),
    path('api/create-checkout-session/', views.CreateCheckoutSessionView.as_view(), name='create-checkout-session'),
    path('api/create-customer-portal/', views.CreateCustomerPortalView.as_view(), name='create-customer-portal'),
    path('api/webhook-endpoint/', views.WebhookEndpointView.as_view(), name='webhook-endpoint'),
    path('api/complete-registration/', views.CompleteRegistrationView.as_view(), name='complete-registration'),
    path('api/subscription-status/', views.SubscriptionStatusView.as_view(), name='subscription-status'),
    path('api/start-chat-session/', views.StartChatSessionView.as_view(), name='start-chat-session'),
    path('api/send-message/', views.SendMessageView.as_view(), name='send-message'),
    path('api/chat-history/', views.ChatHistoryView.as_view(), name='chat-history'),
    path('api/chat-history/<int:session_id>/', views.ChatHistoryView.as_view(), name='chat-history-detail'),
    path('api/deactivate-chat-sessions/', views.DeactivateChatSessionsView.as_view(), name='deactivate-chat-sessions'),
]
