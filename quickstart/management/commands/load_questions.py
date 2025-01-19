import json
from django.core.management.base import BaseCommand
from quickstart.models import SATQuestion
from django.conf import settings
import os

class Command(BaseCommand):
    help = 'Load SAT questions from a JSON file into the database'

    def handle(self, *args, **kwargs):
        file_path = os.path.join(settings.BASE_DIR, 'math_questions.json')
        with open(file_path, 'r') as file:
            questions = json.load(file)
            for question in questions:
                SATQuestion.objects.update_or_create(
                    id=question['id'],
                    defaults={
                        'domain': question['domain'],
                        'question_text': question['question']['question'],
                        'choices': question['question']['choices'],
                        'correct_answer': question['question']['correct_answer'],
                        'explanation': question['question'].get('explanation', ''),
                        'difficulty': question['difficulty'],
                        'visuals': question.get('visuals', {})
                    }
                )
        self.stdout.write(self.style.SUCCESS('Successfully loaded questions into the database'))