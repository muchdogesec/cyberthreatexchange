import json
from django.core.management.base import BaseCommand
from django.db import connection, transaction


class Command(BaseCommand):
    help = "Save, delete, and restore non-unique indexes for a specific table"

    def add_arguments(self, parser):
        parser.add_argument("table", type=str, help="Table name (optionally schema.table)")
        parser.add_argument("--save", type=str, help="File to save indexes")
        parser.add_argument("--delete", action="store_true", help="Delete non-unique indexes")
        parser.add_argument("--restore", type=str, help="Restore indexes from file")
        parser.add_argument('--exclude', nargs='+', help="Dont delete these indexes. e.g ctx_nov_feed_stix_idx, ctx_deduplicator_idx, ctx_nov_empty_query_idx")

    def handle(self, *args, **options):
        table_input = options["table"]
        save_file = options.get("save")
        delete = options.get("delete")
        restore_file = options.get("restore")
        excluded_indexes = options.get("exclude")


        schema, table = self.parse_table(table_input)

        if restore_file:
            self.restore_indexes(restore_file, schema, table)
            return

        if save_file:
            indexes = self.get_indexes(schema, table)

            with open(save_file, "w") as f:
                json.dump(indexes, f, indent=2)

            self.stdout.write(self.style.SUCCESS(
                f"Saved indexes for {schema}.{table} to {save_file}"
            ))

            if delete:
                self.delete_non_unique_indexes(indexes, excluded_indexes)

    def parse_table(self, table_input):
        if "." in table_input:
            schema, table = table_input.split(".", 1)
        else:
            schema = "public"
            table = table_input
        return schema, table

    def get_indexes(self, schema, table):
        query = """
        SELECT
            schemaname,
            tablename,
            indexname,
            indexdef
        FROM pg_indexes
        WHERE schemaname = %s AND tablename = %s;
        """

        with connection.cursor() as cursor:
            cursor.execute(query, [schema, table])
            rows = cursor.fetchall()

        indexes = []
        for schema, table, name, definition in rows:
            indexes.append({
                "schema": schema,
                "table": table,
                "name": name,
                "definition": definition,
                "is_unique": "UNIQUE INDEX" in definition.upper()
            })

        return indexes

    def delete_non_unique_indexes(self, indexes, excluded_indexes):
        self.stdout.write("Deleting non-unique indexes...")

        with connection.cursor() as cursor, transaction.atomic():
            for idx in indexes:
                if not idx["is_unique"] and idx["name"] not in excluded_indexes:
                    sql = f'DROP INDEX IF EXISTS "{idx["schema"]}"."{idx["name"]}";'
                    self.stdout.write(f"Executing: {sql}")
                    cursor.execute(sql)

        self.stdout.write(self.style.SUCCESS("Non-unique indexes deleted."))

    def restore_indexes(self, file_path, schema, table):
        with open(file_path, "r") as f:
            indexes = json.load(f)

        self.stdout.write(f"Restoring indexes for {schema}.{table} from {file_path}...")
        existing_indexes = {v['name']: v for v in self.get_indexes(schema, table)}



        with connection.cursor() as cursor, transaction.atomic():
            for idx in indexes:
                # Safety: only restore for this table
                if idx['name'] in existing_indexes and idx == existing_indexes[idx['name']]:
                    self.stdout.write(f"Skipping existing index: {idx['name']}")
                    continue 
                if idx["schema"] == schema and idx["table"] == table:
                    if not idx["is_unique"]:
                        sql = idx["definition"]
                        self.stdout.write(f"Executing: {sql}")
                        cursor.execute(sql)

        self.stdout.write(self.style.SUCCESS("Indexes restored."))