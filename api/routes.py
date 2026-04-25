"""
ThreatLens AI - Flask Routes
Modular blueprint with all application endpoints.
"""

from flask import Blueprint, render_template, request, session
from utils import PasswordAnalyzer, URLScanner, EmailAnalyzer, KnowledgeBase, QuizManager

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('index.html')


@main.route('/password', methods=['GET', 'POST'])
def password():
    analysis = None
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        analysis = PasswordAnalyzer.analyze(pwd)
    return render_template('password.html', analysis=analysis)


@main.route('/url', methods=['GET', 'POST'])
def url():
    result = None
    if request.method == 'POST':
        url_input = request.form.get('url', '')
        result = URLScanner.scan(url_input)
    return render_template('url.html', result=result)


@main.route('/email', methods=['GET', 'POST'])
def email():
    result = None
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        result = EmailAnalyzer.analyze(email_text)
        # Ensure action field exists for template compatibility
        if result and 'action' not in result:
            if result['risk_level'] == 'HIGH':
                result['action'] = 'Do not click any links. Delete the email and report it to your security team.'
            elif result['risk_level'] == 'MEDIUM':
                result['action'] = 'Be cautious. Verify sender independently before taking any action.'
            else:
                result['action'] = 'Low risk detected, but always remain vigilant.'
    return render_template('email.html', result=result)


@main.route('/ask', methods=['GET', 'POST'])
def ask():
    response = None
    if request.method == 'POST':
        query = request.form.get('question', '')
        response = KnowledgeBase.ask(query)
    return render_template('ask.html', response=response)


@main.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        answers = {k[1:]: int(v) for k, v in request.form.items() if k.startswith('q')}
        quiz_questions = session.get('quiz_questions', [])
        if not quiz_questions:
            quiz_questions = QuizManager.get_quiz(10)
        result = QuizManager.grade(quiz_questions, answers)
        session.pop('quiz_questions', None)
        return render_template('quiz.html', result=result, questions=None)

    questions = QuizManager.get_quiz(10)
    session['quiz_questions'] = questions
    return render_template('quiz.html', questions=questions, result=None)

