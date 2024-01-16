#pragma once

#include <string>

class Logger
{
public:
    static void Log(const char* std, ...);
    static void Log(wchar_t* std, ...);
    static void LogE(const char* std, ...);
    static void LogE(wchar_t* std, ...);
    static void LogD(const char* std, ...);
    static void LogD(wchar_t* std, ...);
};