CONFIG += testcase
TEMPLATE = app
TARGET = tst_qsslocspverifier
DEPENDPATH += .
INCLUDEPATH += .

QT -= gui
QT += network testlib

#CONFIG += release

SOURCES += main.cpp
