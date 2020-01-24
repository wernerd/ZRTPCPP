/*
 * Copyright 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//
// Created by Werner Dittmann on 2020-01-23.
//

#ifndef CALLBACK_SECUREARRAY_H
#define CALLBACK_SECUREARRAY_H

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <string>
#include <stdexcept>

/**
 * @file
 * @ingroup secUtilities
 * @{
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

static inline void wipeMemory(void* data, size_t length) {
    static void * (*volatile memset_volatile)(void *, int, size_t) = std::memset;
    memset_volatile(data, 0, length);
}

#ifndef SECURE_PREALLOCATED
#define SECURE_PREALLOCATED    128
#endif

namespace secUtilities {

    /**
      * @brief Implementation of a secure array class.
     *
     * The SecureArray class provides some features that are needed when writing code
     * that deals with security and handles encryption keys, secure data etc. Within this
     * type of software you often need some arrays to store keys or other sensitive data.
     * It's good practice to wipe the array after using it, in particular if the array
     * was allocated on the heap, but also if it was allocated on the stack. Depending on
     * the allocation of stack frames a locally allocated array may be overwritten more or
     * less immediately or may live some longer time.
     *
     * The SecureArray class behaves roughly like C++ std::array class, however adds some
     * more restrictions and additional features:
     *
     * - Smaller arrays  with a capacity lower the a defined threshold do not allocate heap,
     *   thus behave similar to strings with Small String Optimization, here it's called
     *   Short Array Optimization (SAO). The threshold is 128 bytes by default, however an
     *   application can override this default by defining @c SECURE_PREALLOCATED macro.
     *
     * - On construction the memory is always cleared, thus set to zero (0).
     *
     * - The destructor also clears memory. If memory was allocated from the heap then it's
     *   cleared before returning it to the heap.
     *
     * - During the lifetime of a SecureArray instance at most one heap allocation may happen:
     *   if the requested capacity during construction is larger than the SAO threshold.
     *
     * - During instantiation you can define a maximum capacity of the SecureArray. Code can
     *   access elements only up to the defined capacity, even if the capacity if lower then
     *   the pre-defined SAO threshold.
     *
     * - Accessing elements which are out of range will throw an out-of-range exception if
     *   accessing an element beyond the capacity or beyond the actual size if it's a const
     *   reference for example
     *
     * - A constant copy or constant reference of an existing SecureArray, for example when
     *   handing over as a parameter, return elements only up to the 'filled' size of the array.
     *   Thus you may have a SecureArray for variable key sizes with a capacity of the maximum
     *   key length. The code can now assign some shorter key and hand over the SecureArray
     *   to a function which can check the 'filled' size to determine the actual key length.
     *
     * @code{.cpp}
     * @endcode
     *
     * @note The SecureArray implementation currently supports and uses @c unit8_t
     *       elements only. Enhancing this class to other types is simple: just set the
     *       correct @c value_type in the class. Enhancing this class as a template class
     *       is also possible and should be straight forward. However, for most applications
     *       @c unit8_t is sufficient.
     *
     */
    class SecureArrayBase {
    public:
        using value_type      = uint8_t;
        using size_type       = size_t;

        using reference       = value_type &;
        using const_reference = value_type const &;
        using pointer         = value_type *;
        using const_pointer   = value_type const *;
        using iterator        = pointer;
        using const_iterator  = const_pointer;

        SecureArrayBase() = default;

        explicit SecureArrayBase(size_type capacity) : capacity_(capacity) {
            allocate();
        }

        SecureArrayBase(const_pointer data, size_type length) {
            if (length > capacity_) {
                capacity_ = length;
                allocate();
            }
            append(data, length);
        }

        SecureArrayBase(const SecureArrayBase &other) {
            assign(other);
            capacity_ = other.capacity();
        }

        SecureArrayBase(SecureArrayBase&& other) noexcept {
            capacity_ = other.capacity();
            size_ = other.size();

            // array is larger than pre-allocated thus was allocated on heap. Just steal the pointer
            // and set it to pre-allocated, then set other values to initial states.
            if (other.data_ != other.preAllocated_) {
                data_ = other.data_;
                other.data_ = other.preAllocated_;
                other.size_ = 0;
                other.capacity_ = SECURE_PREALLOCATED;
            } else {
                memcpy(data(), other.data(), size() * sizeof(value_type));
                other.clear();
            }
        }

        ~SecureArrayBase() { reset(); }

        [[nodiscard]] auto
        size() const -> size_type { return size_; }

        [[nodiscard]] auto
        empty() const noexcept -> bool { return size_ == 0; }

        auto
        setSize(size_type newSize) -> void {
            if (newSize > capacity_) throw std::out_of_range("SecureArrayBase::setSize()");
            size_ = newSize;
        }

        [[nodiscard]] auto
        capacity() const -> size_type { return capacity_; }

        [[nodiscard]] auto
        begin() noexcept -> iterator { return iterator(data_); }

        [[nodiscard]] auto
        begin() const noexcept -> const_iterator { return const_iterator(data_); }

        [[nodiscard]] auto
        end() noexcept -> iterator { return iterator(data_ + size()); }

        [[nodiscard]] auto
        end() const noexcept -> const_iterator { return const_iterator(data_ + size()); }

        auto
        at(size_type idx) -> reference {
            if (idx < 0 || idx >= capacity()) throw std::out_of_range("SecureArrayBase::at or operator[]");
            if (idx + 1 > size()) setSize(idx + 1);
            return data_[idx];
        }

        [[nodiscard]] auto
        at(size_type idx) const -> const_reference {
            if (idx < 0 || idx >= size()) throw std::out_of_range("SecureArrayBase::at or operator[]");
            return data_[idx];
        }

        auto
        assign(const SecureArrayBase &x) -> SecureArrayBase & { return assign(x.data(), x.size()); }

        /**
         * @brief Assign data to secure array.
         *
         * The function first checks if the data fits into the secure array and throws an exception
         * in case the data would overflow the capacity. After clearing the internal data (wipe) the
         * function copies the data,
         *
         * @param inData Data to assign
         * @param len length of the data
         * @return Reference to the same secure array.
         */
        auto
        assign(const_pointer inData, size_type len) -> SecureArrayBase & {
            if (len > capacity_) throw std::out_of_range("SecureArrayBase::assign()");
            clear();
            size_ = len;
            memcpy(data(), inData, size() * sizeof(value_type));
            return *this;
        }

        auto
        append(const SecureArrayBase &other) -> SecureArrayBase & { return append(other.data(), other.size()); }

        auto
        append(const_pointer inData, size_type len) -> SecureArrayBase & {
            if (len + size() > capacity()) throw std::out_of_range("SecureArrayBase::append()");

            memcpy(data() + size() * sizeof(value_type), inData, len * sizeof(value_type));
            size_ += len;

            return *this;
        }

        auto
        operator[](size_type idx) -> reference { return at(idx); }

        auto
        operator[](size_type idx) const -> const_reference { return at(idx); }

        auto
        operator=(const SecureArrayBase &x) -> SecureArrayBase & {
            if (this != &x) {
                assign(x);
            }
            return *this;
        }

        auto
        data() noexcept -> pointer { return data_; }

        [[nodiscard]] auto
        data() const noexcept -> const_pointer { return data_; }

        auto
        clear() -> void {
            wipeMemory(data_, capacity_ * sizeof(value_type));
            size_ = 0;
        }

        /**
         * @brief Perform a constant time compare of this secure array with other secure array.
         *
         * The function compares @c len number of @c value_type elements, thus both arrays must have a
         * capacity that's less or equal to the specified length. Otherwise memory access violation
         * may occur.
         *
         * @param other secure byte array to compare with.
         * @param len number of elements
         * @return @c true if data elements are equal
         */
        auto
        cmpConstTime(SecureArrayBase const & other, size_type const len) -> bool {
            pointer in1 = data_;
            pointer in2 = other.data_;

            value_type result = 0;
            for (size_type i = 0; i < len; i++) {
                value_type x = *in1++ ^ *in2++;
                result |= x;
            }
            return result == 0;
        }

    private:
        // reset the class to its initial state. Clear data, return to heap if necessary, set
        // to pre-allocated data, size to 0 and capacity to defined pre-allocated size.
        auto
        reset() -> void {
            clear();
            if (data_ != preAllocated_) {
                delete[] data_;
                data_ = preAllocated_;
            }
            capacity_ = SECURE_PREALLOCATED;
            size_ = 0;
        }

        auto allocate() -> void {
            if (capacity_ > SECURE_PREALLOCATED) {
                data_ = new value_type[capacity_];
                wipeMemory(data_, capacity_ * sizeof(value_type));
            }
        }

        size_type size_ = 0;
        size_type capacity_ = SECURE_PREALLOCATED;
        value_type preAllocated_[SECURE_PREALLOCATED] = {0};
        pointer data_ = preAllocated_;
    };

    template <size_t SIZE>
    class SecureArray : public SecureArrayBase {

    public:
        SecureArray() : SecureArrayBase(SIZE) {};

        constexpr auto
        capacity() -> size_type { return SIZE; }
    };
}

/**
 * @}
 */
#endif //CALLBACK_SECUREARRAY_H
