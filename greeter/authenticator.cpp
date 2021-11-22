/********************************************************************
 KSld - the KDE Screenlocker Daemon
 This file is part of the KDE project.

Copyright (C) 1999 Martin R. Jones <mjones@kde.org>
Copyright (C) 2002 Luboš Luňák <l.lunak@kde.org>
Copyright (C) 2003 Oswald Buddenhagen <ossi@kde.org>
Copyright (C) 2014 Martin Gräßlin <mgraesslin@kde.org>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*********************************************************************/
#include "authenticator.h"
#include <kcheckpass-enums.h>
#include <config-kscreenlocker.h>

// Qt
#include <QCoreApplication>
#include <QFile>
#include <QSocketNotifier>
#include <QTimer>
#include <QDBusMessage>
#include <QDebug>
#include <QDBusConnection>

// system
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

Authenticator::Authenticator(AuthenticationMode mode, QObject *parent)
    : QObject(parent)
    , m_graceLockTimer(new QTimer(this))
    , m_checkPass(nullptr)
{
    m_graceLockTimer->setSingleShot(true);
    m_graceLockTimer->setInterval(100);
    connect(m_graceLockTimer, &QTimer::timeout, this, &Authenticator::graceLockedChanged);

    if (mode == AuthenticationMode::Delayed) {
        m_checkPass = new KCheckPass(AuthenticationMode::Delayed, this);
        setupCheckPass();
    }

    //支持X86翻盖close事件
    QDBusConnection::sessionBus().connect(QStringLiteral(""), QStringLiteral("/org/kde/Solid/PowerManagement"),
                                         QStringLiteral("org.kde.Solid.PowerManagement"), QStringLiteral("lidClosedChanged"),
                                         this, SLOT(lidClosed(bool)));
    QDBusConnection::systemBus().connect(QStringLiteral("com.jingos.repowerd.Screen"), QStringLiteral("/com/jingos/repowerd/Screen"),
                                         QStringLiteral("com.jingos.repowerd.Screen"), QStringLiteral("DisplayPowerStateChange"),
                                         this, SLOT(reviceSlakeScreen(int, int)));

    //添加通知中心删除通知响应
     QDBusConnection::sessionBus().connect(QStringLiteral(), QStringLiteral("/org/jingos/notification"),
        QStringLiteral("org.jingos.notification"), QStringLiteral("closeNotificationId"), this,SLOT(closeNotificationAction(uint)));
}

Authenticator::~Authenticator() = default;

void Authenticator::tryUnlock(const QString &password)
{
    if (isGraceLocked()) {
        emit failed();
        return;
    }
    m_graceLockTimer->start();
    emit graceLockedChanged();

    if (!m_checkPass) {
        m_checkPass = new KCheckPass(AuthenticationMode::Direct, this);
        m_checkPass->setPassword(password);
        setupCheckPass();
    } else {
        if (!m_checkPass->isReady()) {
            emit failed();
            return;
        }
        m_checkPass->setPassword(password);
        m_checkPass->startAuth();
    }
}

void Authenticator::reviceSlakeScreen(int status, int )
{
     emit screenBrightness(status);
}

void Authenticator::lidClosed(bool lidClosed)
{
    qDebug()<<"[liubangguo]reviceSlakeScreen";
    if(lidClosed == true){
        emit screenBrightness(0);
    }
}

void Authenticator::setupCheckPass()
{
    connect(m_checkPass, &KCheckPass::succeeded, this, &Authenticator::succeeded);
    connect(m_checkPass, &KCheckPass::failed, this, &Authenticator::failed);
    connect(m_checkPass, &KCheckPass::message, this, &Authenticator::message);
    connect(m_checkPass, &KCheckPass::error, this, &Authenticator::error);
    connect(m_checkPass, &KCheckPass::destroyed, this,
        [this] {
            m_checkPass = nullptr;
        }
    );
    m_checkPass->start();
}

bool Authenticator::isGraceLocked() const
{
    return m_graceLockTimer->isActive();
}

void Authenticator::resetCheckPass()
{
    if(m_checkPass){
        delete m_checkPass;
        m_checkPass = nullptr;
    }
}

void Authenticator::emitShowViewSig()
{
    emit showViewSig();
}

void Authenticator::closelockScreeNotificationId(uint id)
{
    QDBusMessage message =QDBusMessage::createSignal(QStringLiteral("/org/jingos/lockScreeNotification"), 
            QStringLiteral("org.jingos.lockScreenotification"), QStringLiteral("closelockScreeNotificationId"));
    message << id;

    QDBusConnection::sessionBus().send(message);
}
void Authenticator::closeNotificationAction(uint id)
{
    emit closeNotificationId(id);
}
KCheckPass::KCheckPass(AuthenticationMode mode, QObject *parent)
    : QObject(parent)
    , m_notifier(nullptr)
    , m_pid(0)
    , m_fd(0)
    , m_mode(mode)
{
    if (mode == AuthenticationMode::Direct) {
        connect(this, &KCheckPass::succeeded, this, &QObject::deleteLater);
        connect(this, &KCheckPass::failed, this, &QObject::deleteLater);
    }
}

KCheckPass::~KCheckPass()
{
    reapVerify();
}

void KCheckPass::onSuccessed()
{

//    ::kill(m_pid, SIGBUS);
}

void KCheckPass::onFailed()
{
//    ::kill(m_pid, SIGBUS);
}

void KCheckPass::start()
{
    int sfd[2];
    char fdbuf[16];

    if (m_notifier)
        return;
    if (::socketpair(AF_LOCAL, SOCK_STREAM, 0, sfd)) {
        cantCheck();
        return;
    }
    if ((m_pid = ::fork()) < 0) {
        ::close(sfd[0]);
        ::close(sfd[1]);
        cantCheck();
        return;
    }
    if (!m_pid) {
        ::close(sfd[0]);
        sprintf(fdbuf, "%d", sfd[1]);
        execlp(QFile::encodeName(QStringLiteral(KCHECKPASS_BIN)).data(),
               "kcheckpass",
               "-m", "classic",
               "-S", fdbuf,
               (char *)nullptr);
        _exit(20);
    }
    ::close(sfd[1]);
    m_fd = sfd[0];
    m_notifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_notifier, &QSocketNotifier::activated, this, &KCheckPass::handleVerify);
}

////// kckeckpass interface code

int KCheckPass::Reader(void *buf, int count)
{
    int ret, rlen;

    for (rlen = 0; rlen < count; ) {
      dord:
        ret = ::read(m_fd, (void *)((char *)buf + rlen), count - rlen);
        if (ret < 0) {
            if (errno == EINTR)
                goto dord;
            if (errno == EAGAIN)
                break;
            return -1;
        }
        if (!ret)
            break;
        rlen += ret;
    }
    return rlen;
}

bool KCheckPass::GRead(void *buf, int count)
{
    return Reader(buf, count) == count;
}

bool KCheckPass::GWrite(const void *buf, int count)
{
    return ::write(m_fd, buf, count) == count;
}

bool KCheckPass::GSendInt(int val)
{
    return GWrite(&val, sizeof(val));
}

bool KCheckPass::GSendStr(const char *buf)
{
    int len = buf ? ::strlen (buf) + 1 : 0;
    return GWrite(&len, sizeof(len)) && GWrite (buf, len);
}

bool KCheckPass::GSendArr(int len, const char *buf)
{
    return GWrite(&len, sizeof(len)) && GWrite (buf, len);
}

bool KCheckPass::GRecvInt(int *val)
{
    return GRead(val, sizeof(*val));
}

bool KCheckPass::GRecvArr(char **ret)
{
    int len;
    char *buf;

    if (!GRecvInt(&len))
        return false;
    if (!len) {
        *ret = nullptr;
        return true;
    }
    if (!(buf = (char *)::malloc (len)))
        return false;
    *ret = buf;
    if (GRead (buf, len)) {
        return true;
    } else {
        ::free(buf);
        *ret = nullptr;
        return false;
    }
}

void KCheckPass::handleVerify()
{
    m_ready = false;
    int ret;
    char *arr;

    if (GRecvInt( &ret )) {
        switch (ret) {
        case ConvGetBinary:
            if (!GRecvArr( &arr ))
                break;
            // FIXME: not supported
            cantCheck();
            if (arr)
                ::free( arr );
            return;
        case ConvGetNormal:
        case ConvGetHidden:
        {
            if (!GRecvArr( &arr ))
                break;

            if (m_password.isNull()) {
                GSendStr(nullptr);
            } else {
                QByteArray utf8pass = m_password.toUtf8();
                GSendStr(utf8pass.constData());
                GSendInt(IsPassword);
            }

            m_password.clear();

            if (arr)
                ::free( arr );
            return;
        }
        case ConvPutInfo:
            if (!GRecvArr( &arr ))
                break;
            emit message(QString::fromLocal8Bit(arr));
            ::free( arr );
            return;
        case ConvPutError:
            if (!GRecvArr( &arr ))
                break;
            emit error(QString::fromLocal8Bit(arr));
            ::free( arr );
            return;
        case ConvPutAuthSucceeded:
            emit succeeded();
            return;
        case ConvPutAuthFailed:
            emit failed();
            return;
        case ConvPutAuthError:
            cantCheck();
            return;
        case ConvPutAuthAbort:
        	emit failed();
        	return;
        case ConvPutReadyForAuthentication:
            m_ready = true;
            if (m_mode == AuthenticationMode::Direct) {
                ::kill(m_pid, SIGUSR1);
            }
            return;
        }
    }
    if (m_mode == AuthenticationMode::Direct) {
        reapVerify();
    } else {
        // we broke, let's restart the greeter
        // error code 1 will result in a restart through the system
        qApp->exit(1);
    }
}

void KCheckPass::reapVerify()
{
    m_notifier->setEnabled( false );
    m_notifier->deleteLater();
    m_notifier = nullptr;
    ::close( m_fd );
    int status;
    ::kill(m_pid, SIGUSR2);
    while (::waitpid( m_pid, &status, 0 ) < 0)
        if (errno != EINTR) { // This should not happen ...
            cantCheck();
            return;
        }
}

void KCheckPass::cantCheck()
{
    // TODO: better signal?
    emit failed();
}

void KCheckPass::startAuth()
{
    ::kill(m_pid, SIGUSR1);
}
