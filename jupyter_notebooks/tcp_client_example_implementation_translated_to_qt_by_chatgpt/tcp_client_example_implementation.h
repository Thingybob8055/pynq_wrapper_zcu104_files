// tcpclient.h
#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QObject>
#include <QTcpSocket>

class TCPClient : public QObject
{
    Q_OBJECT

public:
    TCPClient(const QString& server_ip, int server_port, QObject* parent = nullptr);
    ~TCPClient();

    void sendUpdateStatus();
    void sendListPrograms();
    void sendLoadProgram(const QString& programName);
    void sendRun();
    void sendHalt();
    void sendEnableTraining();
    void sendDisableTraining();
    void sendEnableTesting();
    void sendDisableTesting();

signals:
    void messageReceived(const QString& message);

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();

    // Handling RPC return messages
    void handleReturnUpdateStatus(const QJsonObject& rpcReturnJson);
    void handleReturnListPrograms(const QJsonObject& rpcReturnJson);
    void handleReturnLoadProgram(const QJsonObject& rpcReturnJson);
    void handleReturnRun(const QJsonObject& rpcReturnJson);
    void handleReturnHalt(const QJsonObject& rpcReturnJson);
    void handleReturnEnableTraining(const QJsonObject& rpcReturnJson);
    void handleReturnDisableTraining(const QJsonObject& rpcReturnJson);
    void handleReturnEnableTesting(const QJsonObject& rpcReturnJson);
    void handleReturnDisableTesting(const QJsonObject& rpcReturnJson);

private:
    void connectToServer();

    QTcpSocket* socket_;
};

#endif // TCPCLIENT_H
