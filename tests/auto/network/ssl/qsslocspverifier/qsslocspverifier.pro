load(qttest_p4)

SOURCES += tst_qsslocspverifier.cpp
!wince*:win32:LIBS += -lws2_32
QT = core network

TARGET = tst_qsslocspverifier

win32 {
  CONFIG(debug, debug|release) {
    DESTDIR = debug
} else {
    DESTDIR = release
  }
}

wince*|symbian: {
  certFiles.sources = certificates
  certFiles.path    = .
  DEPLOYMENT += certFiles
}

wince*: {
  DEFINES += SRCDIR=\\\".\\\"
} else:!symbian {
   DEFINES += SRCDIR=\\\"$$PWD/\\\"
   TARGET.CAPABILITY = NetworkServices
}
