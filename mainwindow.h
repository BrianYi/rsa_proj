#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "rsa.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
public slots:
    void dealGenerateKeyPair();
    void dealPlainChanged();
    void dealEncrypt();
    void dealDecrypt();
protected:
    rsa_pub_key pubkey;
    rsa_pri_key prikey;
    char *fCipher;
    size_t fCipherSize;
private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
