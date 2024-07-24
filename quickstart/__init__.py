from facebook_business.api import FacebookAdsApi
from django.conf import settings
from facebook_business.adobjects.serverside.content import Content
from facebook_business.adobjects.serverside.custom_data import CustomData 
from facebook_business.adobjects.serverside.delivery_category import DeliveryCategory
from facebook_business.adobjects.serverside.event import Event
from facebook_business.adobjects.serverside.event_request import EventRequest
from facebook_business.adobjects.serverside.gender import Gender
from facebook_business.adobjects.serverside.user_data import UserData
from facebook_business.adobjects.serverside.action_source import ActionSource

access_token = settings.PIXEL_SECRET_KEY
pixel_id = settings.PIXEL_ID

FacebookAdsApi.init(access_token=access_token)
