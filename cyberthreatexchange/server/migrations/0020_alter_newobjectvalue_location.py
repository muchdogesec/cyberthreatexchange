from django.db import migrations


def set_location_knowledgebase(apps, schema_editor):
    NewObjectValue = apps.get_model("cyberthreatexchange", "NewObjectValue")
    NewObjectValue.objects.filter(type="location").update(knowledgebase="location")


class Migration(migrations.Migration):

    dependencies = [
        ("cyberthreatexchange", "0019_newobjectvalue_arango_pk_delete_objectversion"),
    ]

    operations = [
        migrations.RunPython(
            set_location_knowledgebase,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
