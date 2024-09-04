from rest_framework import generics, permissions, filters
from rest_framework.pagination import PageNumberPagination

from .models import Event
from .serializers import EventSerializer
from django_filters.rest_framework import DjangoFilterBackend


class EventListCreate(generics.ListCreateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['date', 'location', 'organizer']
    search_fields = ['title', 'description']
    ordering_fields = ['date', 'title']
    pagination_class = PageNumberPagination

class EventDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
