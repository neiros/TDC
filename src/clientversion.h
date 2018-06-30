#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

//
// client versioning and copyright year                                                 версия клиента и авторских год
//

// These need to be macros, as version.cpp's and bitcoin-qt.rc's voodoo requires it     Они должны быть макросами, поскольку version.cpp и bitcoin-qt.rc's voodoo требует этого
#define CLIENT_VERSION_MAJOR       0
#define CLIENT_VERSION_MINOR       8
#define CLIENT_VERSION_REVISION    217    // 99
#define CLIENT_VERSION_BUILD       7

// Set to true for release, false for prerelease or test build                          Установите true для релиза, false для предварительной или тестовой сборки
#define CLIENT_VERSION_IS_RELEASE  true     // false

// Copyright year (2009-this)
// Todo: update this when changing our copyright comments in the source                 обновите это при изменении наших авторских комментариев в исходниках
#define COPYRIGHT_YEAR 2018     // 2013

// Converts the parameter X to a string after macro replacement on X has been performed.Преобразует значение параметра X в строку после макро замены на X которая была выполнена
// Don't merge these into one macro!                                                    Не объединяйте их в один макрос!
#define STRINGIZE(X) DO_STRINGIZE(X)
#define DO_STRINGIZE(X) #X

#endif // CLIENTVERSION_H
