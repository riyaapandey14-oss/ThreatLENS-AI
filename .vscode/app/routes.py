from flask import Blueprint, render_template, request, session, flash
from flask_login import current_user, login_required
from datetime import datetime
from .services.password_analyzer import PasswordAnalyzer
from .services.url_scanner import URLScanner  
from .services.ai_assistant import AIAnalyst
from .services.risk_engine import RiskEngine
from .models import ScanHistory, db

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template("index.html")

@main.route('/dashboard')
def dashboard():
    scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(10).all()
    return render_template("dashboard.html", scans=scans)

@main.route('/password', methods=["GET", "POST"])
def password():
    analysis = {}
    
    if request.method == "POST":
        pwd = request.form.get("password")
        analysis = PasswordAnalyzer.analyze(pwd)
        
        scan = ScanHistory(
            scan_type='password',
            input_data=pwd[:50], 
            result=str({'score': analysis['score'], 'strength': analysis['strength']}),
            risk_score=5 - analysis['score']  # Invert for risk
        )
        db.session.add(scan)
        db.session.commit()
        
        context = f"Password strength analysis: score={analysis['score']}/5, strength={analysis['strength']}, reason={analysis.get('reason', '')}"
        ai_analysis = AIAnalyst.analyze(context)
        analysis['ai_response'] = ai_analysis.get('analyst_response', 'AI unavailable - check API key')
        if 'reason' in analysis:
            analysis['details'] = analysis['reason'].split('; ')
    
    return render_template("password.html", analysis=analysis)

@main.route('/url', methods=["GET", "POST"])
def url():
    scan_result = {}
    
    if request.method == "POST":
        url_input = request.form.get("url")
        scan_result = URLScanner.scan(url_input)
        
        scan = ScanHistory(
            scan_type='url',
            input_data=url_input[:100],
            result=str({'risk_score': scan_result['risk_score'], 'result': scan_result['result']}),
            risk_score=scan_result['risk_score']
        )
        db.session.add(scan)
        db.session.commit()
        
        context = f"URL risk analysis: risk_score={scan_result['risk_score']}, result={scan_result['result']}, reason={scan_result.get('reason', '')}"
        ai_analysis = AIAnalyst.analyze(context)
        scan_result['ai_response'] = ai_analysis.get('analyst_response', 'AI unavailable - check API key')
    
    return render_template("url.html", scan_result=scan_result)

@main.route('/ai', methods=["GET", "POST"])
def ai():
    conversation = session.get('ai_conversation', [])
    
    if request.method == "POST":
        # Handle both form data and JSON
        if request.is_json:
            query = request.json.get("message")
        else:
            query = request.form.get("message")
        
        if not query:
            return {"error": "No message provided"}, 400
        
        response_data = AIAnalyst.analyze(query)
        
        # Store conversation
        conversation.append({'user': query, 'ai': response_data.get('analyst_response', 'Error')})
        session['ai_conversation'] = conversation[-10:]  # Keep last 10
        
        scan = ScanHistory(
            scan_type='ai',
            input_data=query[:50],
            result=response_data.get('analyst_response', 'Error')[:250],
            risk_score=response_data.get('risk_score', 50)
        )
        db.session.add(scan)
        db.session.commit()
        
        # Return JSON if request was JSON, otherwise render template
        if request.is_json:
            return {
                "analyst_response": response_data.get('analyst_response', 'Error'),
                "risk_score": response_data.get('risk_score', 50),
                "source": response_data.get('source', 'UNKNOWN')
            }
        
        return render_template("ai.html", 
                             analyst_response=response_data.get('analyst_response', 'Error'),
                             conversation=conversation)
    
    return render_template("ai.html", conversation=conversation)

@main.route('/overall-risk', methods=["POST"])
def overall_risk():
    recent_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(3).all()
    
    password_data = {'score': 50}
    url_data = {'risk_score': 50}
    ai_data = {'risk_score': 50}
    
    for scan in recent_scans:
        try:
            data = eval(scan.result) if scan.result else {}
            if scan.scan_type == 'password':
                password_data = {'score': data.get('score', 50)}
            elif scan.scan_type == 'url':
                url_data = {'risk_score': data.get('risk_score', 50)}
            elif scan.scan_type == 'ai':
                ai_data = {'risk_score': scan.risk_score or 50}
        except:
            pass
    
    overall = RiskEngine.calculate_overall_risk(password_data, url_data, ai_data)
    return overall
