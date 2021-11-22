/********************************************************************
 KSld - the KDE Screenlocker Daemon
 This file is part of the KDE project.

 Copyright (C) 1999 Martin R. Jones <mjones@kde.org>
 Copyright (C) 2002 Luboš Luňák <l.lunak@kde.org>
 Copyright (C) 2003 Oswald Buddenhagen <ossi@kde.org>
 Copyright (C) 2008 Chani Armitage <chanika@gmail.com>
 Copyright (C) 2011 Martin Gräßlin <mgraesslin@kde.org>
 Copyright (C) 2015 Bhushan Shah <bhush94@gmail.com>

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

#include "abstractlocker.h"

#include <QScreen>
#include <QPainter>
#include <QApplication>
#include <QtDBus>

#include <KLocalizedString>

namespace ScreenLocker
{

BackgroundWindow::BackgroundWindow(AbstractLocker *lock)
    : QRasterWindow()
    , m_lock(lock)
{
    setFlags(Qt::X11BypassWindowManagerHint | Qt::FramelessWindowHint);
    setProperty("org_kde_ksld_emergency", true);
}

BackgroundWindow::~BackgroundWindow() = default;

void BackgroundWindow::paintEvent(QPaintEvent* )
{
    //[liubangguo]canceled background window
#if defined (__arm64__) || defined (__aarch64__)
    return;
#endif

    QPainter p(this);
    p.fillRect(0, 0, width(), height(), Qt::black);
    if (m_greeterFailure) {
        auto text =    ki18n("The screen locker is broken and unlocking is not possible anymore.\n"
                             "In order to unlock it either ConsoleKit or LoginD is needed, none of\n"
                             "which could be found on your system.");
        auto text_ck = ki18n("The screen locker is broken and unlocking is not possible anymore.\n"
                             "In order to unlock switch to a virtual terminal (e.g. Ctrl+Alt+F2),\n"
                             "log in as root and execute the command:\n\n"
                             "# ck-unlock-session <session-name>\n\n");
        auto text_ld = ki18n("The screen locker is broken and unlocking is not possible anymore.\n"
                             "In order to unlock switch to a virtual terminal (e.g. Ctrl+Alt+F2),\n"
                             "log in and execute the command:\n\n"
                             "loginctl unlock-session %1\n\n"
                             "Afterwards switch back to the running session (Ctrl+Alt+F%2).");

        auto haveService = [](QString service){return QDBusConnection::systemBus().interface()->isServiceRegistered(service);};
        if (haveService(QStringLiteral("org.freedesktop.ConsoleKit"))) {
            text = text_ck;
        } else if (haveService(QStringLiteral("org.freedesktop.login1"))) {
            text = text_ld;
            text = text.subs(QString::fromLocal8Bit(qgetenv("XDG_SESSION_ID")));
            text = text.subs(QString::fromLocal8Bit(qgetenv("XDG_VTNR")));
        }

        p.setPen(Qt::white);
        QFont f = p.font();
        f.setBold(true);
        f.setPointSize(24);
        // for testing emergency mode, we need to disable antialias, as otherwise
        // screen wouldn't be completely black and white.
        if (qEnvironmentVariableIsSet("KSLD_TESTMODE")) {
            f.setStyleStrategy(QFont::NoAntialias);
        }
        p.setFont(f);
        const auto screens = QGuiApplication::screens();
        for (auto s : screens) {
            p.drawText(s->geometry(), Qt::AlignVCenter | Qt::AlignHCenter, text.toString());
        }
    }
    m_lock->stayOnTop();
}

void BackgroundWindow::emergencyShow()
{
    m_greeterFailure = true;
    update();
    show();
}

AbstractLocker::AbstractLocker(QObject *parent)
    : QObject(parent)
{
    if (qobject_cast<QGuiApplication*>(QCoreApplication::instance())) {
        m_background.reset(new BackgroundWindow(this));
    }
}

AbstractLocker::~AbstractLocker()
{
}

void AbstractLocker::emergencyShow()
{
    if (m_background.isNull()) {
        return;
    }
    m_background->emergencyShow();
}

void AbstractLocker::addAllowedWindow(quint32 windows)
{
    Q_UNUSED(windows);
}

}

