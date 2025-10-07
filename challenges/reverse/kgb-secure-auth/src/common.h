#pragma once

#include "words.h"

#include <string>
#include <cstdint>
#include <sstream>

static constexpr size_t WORD_COUNT = 2241;

class WordList
{
public:
    WordList() {
        std::stringstream ss(std::string(reinterpret_cast<const char*>(words_txt), words_txt_len));

        _words->resize(WORD_COUNT);

        for (size_t i = 0; i < WORD_COUNT; ++i) {
            std::getline(ss, _words[i]);
        }
    }

    const std::string& getWord(size_t index) const {
        if (index >= WORD_COUNT) {
            throw std::out_of_range("Index out of range");
        }

        return _words[index];
    }

private:
    std::string _words[WORD_COUNT];
};

class PassphraseGenerator
{
public:
    PassphraseGenerator(uint32_t seed) : _seed(seed)
    {
        _length = generateOne() % 8 + 8;
    }

    uint32_t getLength() const { return _length; }

    uint32_t generateOne()
    {
        _seed = (1103515245 * _seed + 12345) & 0x7fffffff;
        return _seed;
    }

    std::string generateWord()
    {
        uint32_t index = generateOne() % WORD_COUNT;
        return _wordList.getWord(index);
    }

    std::string generateAll()
    {
        std::string result;
        result.reserve(_length);

        for (uint32_t i = 0; i < _length; ++i)
        {
            result += generateWord();

            if (i != _length - 1) {
                result += '-';
            }
        }

        return result;
    }

private:
    WordList _wordList;

    uint32_t _seed;
    uint32_t _length;
};
