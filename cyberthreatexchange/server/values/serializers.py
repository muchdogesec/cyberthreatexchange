

from rest_framework import serializers

from cyberthreatexchange.server.models import NewObjectValue


class ValuesSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewObjectValue
        fields = "__all__"

class ValuesAsStixSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewObjectValue
        fields = []
    
    def to_representation(self, instance):
        obj = self.context['objects'][instance.stix_id]
        return obj