"""Net365 wallet-funded recurring payment scheduler.

Runs inside the Flask process when NET365_SCHEDULER_ENABLED=true.
For multi-worker production deployments, run exactly one scheduler process.
"""
import os
import smtplib
import logging
import json
from email.message import EmailMessage
from datetime import datetime, timedelta, date
from calendar import monthrange
from zoneinfo import ZoneInfo

import database as db

logger = logging.getLogger(__name__)

LABELS = {
    'en': {'amount':'Amount','due':'Due','balance':'Wallet balance','available':'Available','required':'Required','reference':'Reference','remaining':'Remaining wallet balance','reason':'Reason','fund':'Please fund your Net365 wallet to avoid a missed payment.'},
    'fr': {'amount':'Montant','due':'Échéance','balance':'Solde du portefeuille','available':'Disponible','required':'Requis','reference':'Référence','remaining':'Solde restant','reason':'Motif','fund':'Veuillez approvisionner votre portefeuille Net365 pour éviter un paiement manqué.'},
    'de': {'amount':'Betrag','due':'Fällig','balance':'Wallet-Guthaben','available':'Verfügbar','required':'Benötigt','reference':'Referenz','remaining':'Verbleibendes Guthaben','reason':'Grund','fund':'Bitte laden Sie Ihr Net365-Wallet auf, um eine verpasste Zahlung zu vermeiden.'},
    'ar': {'amount':'المبلغ','due':'الاستحقاق','balance':'رصيد المحفظة','available':'المتاح','required':'المطلوب','reference':'المرجع','remaining':'الرصيد المتبقي','reason':'السبب','fund':'يرجى تمويل محفظة Net365 لتجنب فشل الدفع.'},
    'zh': {'amount':'金额','due':'到期时间','balance':'钱包余额','available':'可用余额','required':'所需金额','reference':'参考号','remaining':'剩余钱包余额','reason':'原因','fund':'请为 Net365 钱包充值，以避免付款失败。'},
    'es': {'amount':'Importe','due':'Vencimiento','balance':'Saldo de cartera','available':'Disponible','required':'Necesario','reference':'Referencia','remaining':'Saldo restante','reason':'Motivo','fund':'Añade fondos a tu cartera Net365 para evitar un pago fallido.'},
    'pt': {'amount':'Valor','due':'Vencimento','balance':'Saldo da carteira','available':'Disponível','required':'Necessário','reference':'Referência','remaining':'Saldo restante','reason':'Motivo','fund':'Adicione fundos à sua carteira Net365 para evitar um pagamento perdido.'}
}

LANG = {
    'en': {'due':'Upcoming scheduled payment','low':'Wallet balance may be insufficient','success':'Scheduled payment successful','failed':'Scheduled payment failed'},
    'fr': {'due':'Paiement programmé à venir','low':'Le solde du portefeuille peut être insuffisant','success':'Paiement programmé réussi','failed':'Échec du paiement programmé'},
    'de': {'due':'Bevorstehende geplante Zahlung','low':'Das Wallet-Guthaben könnte nicht ausreichen','success':'Geplante Zahlung erfolgreich','failed':'Geplante Zahlung fehlgeschlagen'},
    'ar': {'due':'دفعة مجدولة قادمة','low':'قد لا يكون رصيد المحفظة كافياً','success':'تم الدفع المجدول بنجاح','failed':'فشل الدفع المجدول'},
    'zh': {'due':'即将进行的计划付款','low':'钱包余额可能不足','success':'计划付款成功','failed':'计划付款失败'},
    'es': {'due':'Pago programado próximo','low':'El saldo de la cartera puede ser insuficiente','success':'Pago programado realizado','failed':'Pago programado fallido'},
    'pt': {'due':'Pagamento agendado próximo','low':'O saldo da carteira pode ser insuficiente','success':'Pagamento agendado concluído','failed':'Pagamento agendado falhou'},
}


def _tz(name):
    try:
        return ZoneInfo(name or os.getenv('NET365_DEFAULT_TIMEZONE','Africa/Lagos'))
    except Exception:
        return ZoneInfo('Africa/Lagos')


def _parse_dt(value, tz):
    if not value:
        return None
    try:
        dt=datetime.fromisoformat(str(value).replace('Z','+00:00'))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=tz)
        return dt.astimezone(tz)
    except Exception:
        return None


def _next_occurrence(s, after=None):
    tz=_tz(s.get('timezone'))
    now=after.astimezone(tz) if after else datetime.now(tz)
    freq=(s.get('frequency') or 'monthly').lower()
    hour=int(s.get('hour') or 0); minute=int(s.get('minute') or 1)
    if freq=='once':
        return _parse_dt(s.get('run_at'),tz)
    if freq=='daily':
        candidate=now.replace(hour=hour,minute=minute,second=0,microsecond=0)
        return candidate if candidate>now else candidate+timedelta(days=1)
    if freq=='weekly':
        target=int(s.get('day_of_week') or 0)
        delta=(target-now.weekday())%7
        candidate=(now+timedelta(days=delta)).replace(hour=hour,minute=minute,second=0,microsecond=0)
        if candidate<=now: candidate+=timedelta(days=7)
        return candidate
    if freq=='monthly':
        dom=max(1,int(s.get('day_of_month') or 1))
        y,m=now.year,now.month
        for _ in range(24):
            dom2=min(dom,monthrange(y,m)[1])
            candidate=datetime(y,m,dom2,hour,minute,tzinfo=tz)
            if candidate>now:return candidate
            m+=1
            if m>12:y,m=y+1,1
        return None
    if freq=='yearly':
        month=max(1,min(12,int(s.get('month') or 1))); dom=max(1,int(s.get('day_of_month') or 1))
        y=now.year
        for _ in range(3):
            dom2=min(dom,monthrange(y,month)[1])
            candidate=datetime(y,month,dom2,hour,minute,tzinfo=tz)
            if candidate>now:return candidate
            y+=1
        return None
    return None


def _human_service(s):
    if s.get('service_type')=='airtime':
        return f"{s.get('operator_name') or 'Mobile network'} • {s.get('phone') or ''}".strip(' •')
    return f"{s.get('name') or 'Utility payment'} • {s.get('subscriber_account') or ''}".strip(' •')


def _send_email(user, subject, body, lang='en'):
    host=os.getenv('SMTP_HOST'); port=int(os.getenv('SMTP_PORT','587')); username=os.getenv('SMTP_USERNAME'); password=os.getenv('SMTP_PASSWORD'); sender=os.getenv('SMTP_FROM') or username
    if not host or not sender or not user.get('email'):
        logger.info('Email not sent: SMTP not configured or user has no email')
        return False
    msg=EmailMessage(); msg['Subject']=subject; msg['From']=sender; msg['To']=user['email']; msg.set_content(body)
    try:
        with smtplib.SMTP(host,port,timeout=20) as smtp:
            if os.getenv('SMTP_TLS','true').lower()=='true': smtp.starttls()
            if username: smtp.login(username,password or '')
            smtp.send_message(msg)
        return True
    except Exception as e:
        logger.exception('Scheduled email failed: %s',e); return False


def _labels(user_id):
    settings=db.get_settings(user_id) or {}; lang=(settings.get('language') or 'en').split('-')[0]
    return LABELS.get(lang,LABELS['en'])


def notify_user(user_id,title_key,message,kind='info',email_subject=None):
    user=db.get_user(user_id) or {}; settings=db.get_settings(user_id) or {}; lang=(settings.get('language') or 'en').split('-')[0]
    lang=lang if lang in LANG else 'en'
    title=LANG[lang][title_key]
    db.create_notification(user_id,title,message,kind)
    if settings.get('email_notifications',1) and email_subject:
        _send_email(user,email_subject,message,lang)


def _next_and_retry(s, base):
    next_run=_next_occurrence(s,base)
    return next_run


class Net365Scheduler:
    def __init__(self, executor, interval_seconds=30):
        self.executor=executor
        self.interval_seconds=interval_seconds
        self._thread=None
        self._stop=False

    def start(self):
        if os.getenv('NET365_SCHEDULER_ENABLED','true').lower()!='true':
            logger.info('Net365 scheduler disabled by NET365_SCHEDULER_ENABLED')
            return
        if self._thread and self._thread.is_alive(): return
        import threading
        self._stop=False
        self._thread=threading.Thread(target=self._loop,name='net365-scheduler',daemon=True)
        self._thread.start()
        logger.info('Net365 scheduler started')

    def stop(self): self._stop=True

    def _loop(self):
        while not self._stop:
            try:
                self.tick()
            except Exception:
                logger.exception('Scheduler tick failed')
            import time; time.sleep(self.interval_seconds)

    def tick(self):
        now=datetime.utcnow().replace(second=0,microsecond=0)
        schedules=db.get_active_schedules_for_notification()
        for s in schedules:
            self._notifications(s,now)
            tz=_tz(s.get('timezone'))
            local_now=now.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)
            due=_parse_dt(s.get('next_run_at'),tz)
            if due and due <= local_now:
                self._run_due(s,now)

    def _notifications(self,s,utcnow):
        tz=_tz(s.get('timezone')); now=utcnow.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)
        next_run=_parse_dt(s.get('next_run_at'),tz) or _next_occurrence(s,now-timedelta(minutes=1))
        if not next_run:return
        days=int(s.get('notify_days_before') or 3)
        delta=next_run-now
        if timedelta(0)<=delta<=timedelta(days=days):
            key=next_run.date().isoformat()
            if s.get('last_pre_notice_for')!=key:
                wallet=db.get_wallet(s['user_id']) or {}; balance=float(wallet.get('balance') or 0); amount=float(s['amount'])
                service=_human_service(s)
                l=_labels(s['user_id']); msg=f"{service}\n{l['amount']}: {s.get('currency','NGN')} {amount:,.2f}\n{l['due']}: {next_run.strftime('%Y-%m-%d %H:%M %Z')}\n{l['balance']}: {s.get('currency','NGN')} {balance:,.2f}."
                notify_user(s['user_id'],'due',msg,'info',f"Net365: {s.get('name','Scheduled payment')} is due soon")
                db.set_schedule_notice(s['id'],'last_pre_notice_for',key)
                if balance<amount:
                    db.set_schedule_notice(s['id'],'last_low_balance_notice_date',key)
            elif float((db.get_wallet(s['user_id']) or {}).get('balance') or 0)<float(s['amount']) and s.get('low_balance_daily'):
                today=now.date().isoformat()
                if s.get('last_low_balance_notice_date')!=today:
                    balance=float((db.get_wallet(s['user_id']) or {}).get('balance') or 0); amount=float(s['amount'])
                    l=_labels(s['user_id']); msg=f"{_human_service(s)}\n{l['required']}: {s.get('currency','NGN')} {amount:,.2f}\n{l['available']}: {s.get('currency','NGN')} {balance:,.2f}\n{l['fund']}"
                    notify_user(s['user_id'],'low',msg,'warning',f"Net365: insufficient wallet balance for {s.get('name','scheduled payment')}")
                    db.set_schedule_notice(s['id'],'last_low_balance_notice_date',today)

    def _run_due(self,s,utcnow):
        user=db.get_user(s['user_id']) or {}; wallet=db.get_wallet(s['user_id']) or {}; balance=float(wallet.get('balance') or 0); amount=float(s['amount'])
        if balance<amount:
            retry_until=_parse_dt(s.get('retry_until'),_tz(s.get('timezone')))
            tz=_tz(s.get('timezone')); local=utcnow.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)
            if not retry_until: retry_until=local+timedelta(days=int(s.get('retry_days') or 3))
            if local<=retry_until:
                next_retry=local+timedelta(days=1)
                db.update_scheduled_after_attempt(s['id'],'insufficient_funds',next_retry.isoformat(),retry_until.isoformat(),{'error':'Insufficient wallet balance'},int(s.get('failure_count') or 0)+1)
                return
            # Give up this occurrence and move to the next recurring occurrence.
            next_run=_next_occurrence(s,local)
            db.update_scheduled_after_attempt(s['id'],'active' if next_run else 'completed',next_run.isoformat() if next_run else None,None,{'error':'Insufficient wallet balance; occurrence skipped'},int(s.get('failure_count') or 0)+1)
            notify_user(s['user_id'],'failed',f"{_human_service(s)} could not be paid because the wallet remained below {s.get('currency','NGN')} {amount:,.2f}.",'error',f"Net365: scheduled payment missed")
            return
        try:
            result=self.executor(s)
            if not result.get('success'): raise RuntimeError(result.get('error') or 'Payment failed')
            tz=_tz(s.get('timezone')); local=utcnow.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)
            next_run=_next_occurrence(s,local)
            status='active' if next_run else 'completed'
            ref=result.get('reference') or f"SCH-{s['id']}-{int(utcnow.timestamp())}"
            db.record_scheduled_run(s['id'],s['user_id'],ref,s.get('next_run_at'),amount,s.get('currency','NGN'),'completed',provider_transaction_id=result.get('transactionId'),result=result)
            db.update_scheduled_after_attempt(s['id'],status,next_run.isoformat() if next_run else None,None,result,0)
            remaining=float((db.get_wallet(s['user_id']) or {}).get('balance') or 0)
            l=_labels(s['user_id']); msg=f"{_human_service(s)}\n{l['amount']}: {s.get('currency','NGN')} {amount:,.2f}\n{l['reference']}: {ref}\n{l['remaining']}: {s.get('currency','NGN')} {remaining:,.2f}."
            notify_user(s['user_id'],'success',msg,'success',f"Net365: {s.get('name','Scheduled payment')} completed")
        except Exception as e:
            logger.exception('Scheduled payment failed for schedule %s',s['id'])
            tz=_tz(s.get('timezone')); local=utcnow.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz); next_run=_next_occurrence(s,local)
            db.record_scheduled_run(s['id'],s['user_id'],f"SCH-FAIL-{s['id']}-{int(utcnow.timestamp())}",s.get('next_run_at'),amount,s.get('currency','NGN'),'failed',error=str(e),result={'error':str(e)})
            db.update_scheduled_after_attempt(s['id'],'active' if next_run else 'failed',next_run.isoformat() if next_run else None,None,{'error':str(e)},int(s.get('failure_count') or 0)+1)
            notify_user(s['user_id'],'failed',f"{_human_service(s)}\nAmount: {s.get('currency','NGN')} {amount:,.2f}\nReason: {str(e)}",'error',f"Net365: scheduled payment failed")
