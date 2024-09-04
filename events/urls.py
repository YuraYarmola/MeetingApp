from django.urls import path
from .views import EventListCreate, EventDetail

urlpatterns = [
    path('events/', EventListCreate.as_view(), name='event-list-create'),
    path('events/<int:pk>/', EventDetail.as_view(), name='event-detail'),

]