/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWebView/WebAuthn.h>
#include <UI/Qt/StringUtils.h>
#include <UI/Qt/WebAuthnDialog.h>

#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QThread>
#include <QVBoxLayout>
#include <atomic>

namespace Ladybird {

using WebView::WebAuthn::Account;
using WebView::WebAuthn::AuthenticatorRequest;
using WebView::WebAuthn::Cancellation;
using WebView::WebAuthn::Outcome;
using WebView::WebAuthn::PinStatus;
using WebView::WebAuthn::Result;
using WebView::WebAuthn::SecurityKey;
using Error = WebView::WebAuthn::Error;

class WebAuthnDialog final : public QDialog {
public:
    WebAuthnDialog(QWidget* parent, AuthenticatorRequest request, Function<void(Result)> complete)
        : QDialog(parent)
        , m_request(AK::move(request))
        , m_complete(AK::move(complete))
    {
        m_elapsed.start();
        setAttribute(Qt::WA_DeleteOnClose);
        setWindowTitle("Security key");
        setWindowModality(Qt::WindowModal);

        auto* layout = new QVBoxLayout(this);
        auto* origin = new QLabel(this);
        origin->setTextFormat(Qt::PlainText);
        origin->setText(qstring_from_ak_string(m_request.origin));
        layout->addWidget(origin);
        m_status = new QLabel(m_request.creation.has_value() ? "Create a passkey on a security key." : "Sign in with a security key.", this);
        m_status->setTextFormat(Qt::PlainText);
        layout->addWidget(m_status);
        m_choices = new QComboBox(this);
        layout->addWidget(m_choices);
        m_pin = new QLineEdit(this);
        m_pin->setEchoMode(QLineEdit::Password);
        m_pin->setPlaceholderText("Security key PIN");
        m_pin->hide();
        layout->addWidget(m_pin);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
        m_continue = buttons->addButton("Continue", QDialogButtonBox::AcceptRole);
        m_continue->setEnabled(false);
        layout->addWidget(buttons);

        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        connect(m_continue, &QPushButton::clicked, this, [this] { proceed(); });
        connect(this, &QDialog::finished, this, [this] {
            if (m_complete)
                finish(Error::NotAllowed);
        });

        run([] { return WebView::WebAuthn::enumerate_security_keys(); }, [this](Vector<SecurityKey> keys) { did_find_keys(AK::move(keys)); });
    }

    virtual ~WebAuthnDialog() override
    {
        m_cancellation->cancel();
    }

    void dismiss()
    {
        m_complete = {};
        m_cancellation->cancel();
        reject();
    }

private:
    void finish(Result result)
    {
        m_cancellation->cancel();
        auto complete = AK::move(m_complete);
        close();
        if (complete)
            complete(AK::move(result));
    }

    // Runs blocking work off the main thread, then hands its result to done if the dialog is still waiting for it.
    // NB: The worker does not belong to the dialog, so that closing a tab never waits for a blocking HID operation.
    template<typename Work, typename Done>
    void run(Work work, Done done)
    {
        auto* worker = QThread::create([guard = QPointer { this }, work = AK::move(work), done = AK::move(done)]() mutable {
            auto deliver = [guard, result = work(), done = AK::move(done)]() mutable {
                if (guard && guard->m_complete)
                    done(AK::move(result));
            };
            QMetaObject::invokeMethod(qApp, AK::move(deliver), Qt::QueuedConnection);
        });
        connect(worker, &QThread::finished, worker, &QObject::deleteLater);
        worker->start();
    }

    void proceed()
    {
        if (!m_accounts.is_empty()) {
            finish(AK::move(m_accounts[m_choices->currentIndex()].response));
            return;
        }
        if (m_pin->text().contains(QChar('\0'))) {
            m_status->setText("The PIN must not contain null characters.");
            return;
        }
        auto elapsed = static_cast<u64>(m_elapsed.elapsed());
        if (elapsed >= m_request.timeout) {
            finish(Error::NotAllowed);
            return;
        }

        // Do not race another ceremony, including a canceled ceremony whose device I/O is still draining.
        static std::atomic_flag authenticator_busy = ATOMIC_FLAG_INIT;
        if (authenticator_busy.test_and_set()) {
            m_status->setText("A security key operation is still finishing. Please try again.");
            return;
        }

        auto path = m_keys[m_choices->currentIndex()].path;
        auto pin_utf8 = m_pin->text().toUtf8();
        auto pin = String::from_utf8_with_replacement_character({ pin_utf8.constData(), static_cast<size_t>(pin_utf8.size()) });
        pin_utf8.fill('\0');
        m_pin->clear();
        m_pin->hide();
        m_continue->setEnabled(false);
        m_choices->setEnabled(false);
        m_status->setText("Touch your security key. Follow any instructions on the key.");

        auto request = m_request;
        request.timeout -= elapsed;
        auto work = [request = AK::move(request), path = AK::move(path), pin = AK::move(pin), cancellation = m_cancellation] {
            auto outcome = WebView::WebAuthn::perform(request, path, pin, *cancellation);
            authenticator_busy.clear();
            return outcome;
        };
        run(AK::move(work), [this](Outcome outcome) { did_perform(AK::move(outcome)); });
    }

    void did_find_keys(Vector<SecurityKey> keys)
    {
        if (keys.is_empty()) {
            m_status->setText("No security key was found. Connect a FIDO2 USB key and try again.");
            return;
        }
        m_keys = AK::move(keys);
        for (auto const& key : m_keys)
            m_choices->addItem(qstring_from_ak_string(key.name));
        m_continue->setEnabled(true);
    }

    void did_perform(Outcome outcome)
    {
        outcome.visit(
            [&](PinStatus status) {
                m_status->setText(status == PinStatus::Invalid ? "Incorrect PIN. Try again, or cancel to avoid locking your key." : "Enter your security key PIN, then continue.");
                m_pin->show();
                m_pin->setFocus();
                m_continue->setEnabled(true);
            },
            [&](Error error) { finish(error); },
            [&](Vector<Account>& accounts) {
                if (accounts.size() == 1) {
                    finish(AK::move(accounts.first().response));
                    return;
                }
                m_accounts = AK::move(accounts);
                m_choices->clear();
                for (auto const& account : m_accounts)
                    m_choices->addItem(qstring_from_ak_string(account.name));
                m_choices->setEnabled(true);
                m_status->setText("Choose the account to sign in with.");
                m_continue->setEnabled(true);
            });
    }

    AuthenticatorRequest m_request;
    Vector<SecurityKey> m_keys;
    Vector<Account> m_accounts;
    NonnullRefPtr<Cancellation> m_cancellation { Cancellation::create() };
    QElapsedTimer m_elapsed;
    Function<void(Result)> m_complete;
    QLabel* m_status { nullptr };
    QComboBox* m_choices { nullptr };
    QLineEdit* m_pin { nullptr };
    QPushButton* m_continue { nullptr };
};

Function<void()> request_webauthn(QWidget* parent, AuthenticatorRequest request, Function<void(Result)> complete)
{
    auto* dialog = new WebAuthnDialog(parent, AK::move(request), AK::move(complete));
    dialog->open();
    return [dialog = QPointer { dialog }] {
        if (dialog)
            dialog->dismiss();
    };
}

}
