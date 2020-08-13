#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    fCipher = nullptr;
    fCipherSize = 0;

    rsa_init();

    // bind slots
    connect(ui->btnGenerateKeyPair, SIGNAL(clicked()), this, SLOT(dealGenerateKeyPair()));
    connect(ui->txtPlain, SIGNAL(textChanged()), this, SLOT(dealPlainChanged()));
    connect(ui->btnEncrypt, SIGNAL(clicked()), this, SLOT(dealEncrypt()));
    connect(ui->btnDecrypt, SIGNAL(clicked()), this, SLOT(dealDecrypt()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dealGenerateKeyPair()
{
    unsigned long long P, Q;
    rsa_gen_key(&pubkey,&prikey, &P, &Q);
    ui->ledtP->setText(QString::number(P));
    ui->ledtQ->setText(QString::number(Q));
    ui->ledtPubKeyN->setText(QString::number(pubkey.n));
    ui->ledtPubKeyE->setText(QString::number(pubkey.e));
    ui->ledtPriKeyN->setText(QString::number(prikey.n));
    ui->ledtPriKeyD->setText(QString::number(prikey.d));
}

void MainWindow::dealPlainChanged()
{
    string plain = ui->txtPlain->toPlainText().toStdString();
    size_t plain_size = plain.size();
    char *pPlainHexStr = nullptr;
    size_t plain_hexstr_size;
    rsa_bin2str((const unsigned char *)plain.c_str(), plain_size, &pPlainHexStr, &plain_hexstr_size, true);
    QString plainStr(pPlainHexStr);
    ui->txtPlainHexStr->setText(plainStr);
}

void MainWindow::dealEncrypt()
{
    string plainStr = ui->txtPlain->toPlainText().toStdString();
    if (fCipher)
    {
        free(fCipher);
        fCipherSize = 0;
    }
    rsa_encrypt(&pubkey, plainStr.c_str(), plainStr.size(), &fCipher, &fCipherSize);

    char *pCipherHexStr;
    size_t cipher_hexstr_size;
    rsa_bin2str((unsigned char *)fCipher, fCipherSize, &pCipherHexStr, &cipher_hexstr_size, true);
    ui->txtCipher->setText(QString::fromLocal8Bit(pCipherHexStr, cipher_hexstr_size));
}

void MainWindow::dealDecrypt()
{
    char *pPlain = nullptr;
    size_t plain_size;
    rsa_decrypt(&prikey, fCipher, fCipherSize, &pPlain, &plain_size);
    ui->txtCipher->setText(QString::fromLocal8Bit(pPlain, plain_size));
    free(pPlain);
}

