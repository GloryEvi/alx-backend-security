from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP
from django.core.exceptions import ValidationError


class Command(BaseCommand):
    help = 'Block an IP address by adding it to the BlockedIP model'

    def add_arguments(self, parser):
        parser.add_argument('ip_address', type=str, help='IP address to block')

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        
        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(ip_address=ip_address)
            
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully blocked IP address: {ip_address}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP address {ip_address} is already blocked')
                )
                
        except ValidationError as e:
            raise CommandError(f'Invalid IP address: {ip_address}')
        except Exception as e:
            raise CommandError(f'Error blocking IP address: {str(e)}')