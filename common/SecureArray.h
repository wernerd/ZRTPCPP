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
// Created by Werner Dittmann on 2020-01-17.
//

#ifndef SEC_UTILS_SECURE_ARRAY_H
#define SEC_UTILS_SECURE_ARRAY_H

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

#ifndef SECURE_PRE_ALLOCATED
#define SECURE_PRE_ALLOCATED    128
#endif

namespace secUtilities {

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

        /**
         * @brief Current size.
         *
         * @return Number of elements in the secure array.
         */
        [[nodiscard]] virtual auto
        size() const -> size_type = 0;

        /**
         * @brief Check if secure array is empty.
         *
         * @return @c true is secure array is empty.
         */
        [[nodiscard]] auto
        empty() const noexcept -> bool { return size() == 0; }

        /**
         * @brief Capacity of the array.
         *
         * @return Maximum number of elements in the secure array.
         */
        [[nodiscard]] virtual auto
        capacity() const -> size_type const = 0;

        /**
         * @brief Begin iterator of secure array.
         *
         * @return Begin iterator.
         */
        [[nodiscard]] auto
        begin() noexcept -> iterator { return iterator(data()); }

        /**
         * @brief Constant begin iterator of secure array.
         *
         * @return Constant begin iterator.
         */
        [[nodiscard]] auto
        begin() const noexcept -> const_iterator { return const_iterator(data()); }

        /**
         * @brief End iterator of secure array.
         *
         * @return End iterator.
         */
        [[nodiscard]] auto
        end() noexcept -> iterator { return iterator(data() + size()); }

        /**
         * @brief Constant end iterator of secure array.
         *
         * @return Constant end iterator.
         */
        [[nodiscard]] auto
        end() const noexcept -> const_iterator { return const_iterator(data() + size()); }

        /**
         * @brief Return the element at given index.
         *
         * If @c index is larger than the current size (available data) then the function adjusts the
         * size and returns the value at that index which is usually the default initialize value.
         *
         * If @c index exceeds @c capacity the function throws an @c out_of_range exception.
         *
         * @param index Index into SecureArray
         * @return the value at index
         * @throws out_of_range
         */
        auto
        at(size_type index) -> reference {
            if (index < 0 || index >= capacity())
                throw std::out_of_range("const SecureArrayBase::at or operator[], idx: " + std::to_string(index) + ", capacity: " + std::to_string(capacity()));

            if (index + 1 > size()) size(index + 1);
            return data()[index];
        }

        /**
         * @brief Return the element at given index.
         *
         * If @c index is larger than the current size (available data) then the function throws an
         * @c out_of_range exception because the instance is a @c const_reference and the function
         * cannot modify the instance.
         *
         * @param index Index into SecureArray
         * @return the value at index
         * @throws out_of_range
         */
        [[nodiscard]] auto
        at(size_type idx) const -> const_reference {
            if (idx < 0 || idx >= size())
                throw std::out_of_range("const SecureArrayBase::at or operator[], idx: " + std::to_string(idx) + ", size: " + std::to_string(size()));
            return data()[idx];
        }

        /**
         * @brief Assign data of one secure array to another.
         *
         * The capacity of the receiving secure array must be large enough to store @c size()
         * number of elements of the @c from secure array.
         *
         * @param from Secure array to copy from.
         * @return Reference to the same secure array.
         * @throws out_of_range
         */
        auto
        assign(const SecureArrayBase &from) -> SecureArrayBase & { return assign(from.data(), from.size()); }

        /**
         * @brief Assign data to secure array.
         *
         * The function first checks if the data fits into the secure array and throws an exception
         * in case the data would overflow the capacity. After clearing the internal data (wipe) the
         * function copies the data.
         *
         * @param inData Data to assign
         * @param len length of the data
         * @return Reference to the same secure array.
         * @throws out_of_range
         */
        auto
        assign(const_pointer inData, size_type len) -> SecureArrayBase & {
            if (len > capacity())
                throw std::out_of_range("SecureArrayBase::assign(), len: " + std::to_string(len) + ", capacity: " + std::to_string(capacity()));
            clear();
            size(len);
            memcpy(data(), inData, size() * sizeof(value_type));
            return *this;
        }

        /**
         * @brief Append data of one secure array to another.
         *
         * The capacity of the receiving secure array must be large enough to append @c size()
         * number of elements of the @c from secure array.
         *
         * Throws an exception in case the data would overflow the capacity.
         *
         * @param from Secure array to append from.
         * @return Reference to the same secure array.
         * @throws out_of_range
         */
        auto
        append(const SecureArrayBase &other) -> SecureArrayBase & { return append(other.data(), other.size()); }

        /**
         * @brief Append data to secure array.
         *
         * The function first checks if the data fits into the secure array and throws an exception
         * in case the data would overflow the capacity.
         *
         * @param inData Data to append.
         * @param len length of the data.
         * @return Reference to the same secure array.
         * @throws out_of_range
         */
        auto
        append(const_pointer inData, size_type len) -> SecureArrayBase & {
            if (len + size() > capacity())
                throw std::out_of_range("SecureArrayBase::assign(), len: " + std::to_string(len+size()) + ", capacity: " + std::to_string(capacity()));

            memcpy(data() + size() * sizeof(value_type), inData, len * sizeof(value_type));
            size(size() + len);

            return *this;
        }

        /**
         * @brief Return the element at given index.
         *
         * If @c index is larger than the current size (available data) then the function adjusts the
         * size and returns the value at that index which is usually the default initialize value.
         *
         * If @c index exceeds @c capacity the function throws an @c out_of_range exception.
         *
         * @param index Index into SecureArray
         * @return the value at index
         * @throws out_of_range
         */
        auto
        operator[](size_type idx) -> reference { return at(idx); }

        /**
         * @brief Return the element at given index.
         *
         * If @c index is larger than the current size (available data) then the function throws an
         * @c out_of_range exception because the instance is a @c const_reference and the function
         * cannot modify the instance.
         *
         * @param index Index into SecureArray
         * @return the value at index
         * @throws out_of_range
         */
        auto
        operator[](size_type idx) const -> const_reference { return at(idx); }

        /**
         * @brief Get pointer to data of secure array.
         *
         * @return Pointer to secure array
         */
        virtual auto
        data() noexcept -> pointer = 0;

        /**
         * @brief Get pointer to constant data of secure array.
         *
         * @return Pointer constant to secure array
         */
        [[nodiscard]] virtual auto
        data() const noexcept -> const_pointer = 0;

        /**
         * @brief Clear the secure array.
         *
         * Wipes the data and sets @c size to 0.
         */
        auto
        clear() -> void {
            wipeMemory(data(), capacity() * sizeof(value_type));
            size(0);
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
            const_pointer in1 = data();
            const_pointer in2 = other.data();

            value_type result = 0;
            for (size_type i = 0; i < len; i++) {
                value_type x = *in1++ ^ *in2++;
                result |= x;
            }
            return result == 0;
        }

        virtual auto
        size(size_type newSize) -> void = 0;

        virtual auto
        capacity(size_type cap) -> void = 0;

        virtual auto
        data(pointer data) -> void = 0;

        virtual auto
        preAllocated() -> pointer  = 0;
    };

    /**
      * @brief Implementation of a secure array class.
     *
     * The SecureArray classes provides some features that are needed when writing code
     * that deals with security and handles encryption keys, secure data etc. Within this
     * type of software you often need some arrays to store keys or other sensitive data.
     * It's good practice to wipe the array after using it, in particular if the array
     * was allocated on the heap, but also if it was allocated on the stack. Depending on
     * the allocation of stack frames a locally allocated array may be overwritten more or
     * less immediately or may live some longer time.
     *
     * The SecureArray classes behaves roughly like C++ std::array class, however adds some
     * more restrictions and additional features:
     *
     * - SecureArray template class allocates as much storage as requested in the template
     *   parameter. This works well if the application knows the size of the array in advance,
     *   for example length of hash output or length oy keys, etc.
     *
     * - SecureArrayFlex class is able to allocate its space during runtime. Smaller arrays
     *   with a capacity lower than a defined threshold do not allocate heap storage,
     *   thus behave similar to std::string with Small String Optimization, here it's called
     *   Short Array Optimization (SAO). The threshold is 128 bytes by default, however an
     *   application can override this default by defining @c SECURE_PRE_ALLOCATED macro.
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
     *   handing over as a parameter, operator [] or @c at function return elements only up to
     *   the 'filled' size of the array. Thus you may have a SecureArray for variable key sizes
     *   with a capacity of the maximum key length. The code can now assign some shorter key
     *   and hand over the SecureArray to a function which can use data up to the 'filled' size.
     *
     * @code{.cpp}
     * @endcode
     *
     * @note The SecureArray implementation currently supports and uses @c unit8_t
     *       elements only. Enhancing this class to other types is possible: set the
     *       correct @c value_type in the class.
     */
    class SecureArrayFlex : public SecureArrayBase {

    public:
        /**
         * @brief SecureArray with default capacity
         */
        SecureArrayFlex() = default;

        /**
         * @brief SecureArray with given capacity
         */
        explicit SecureArrayFlex(size_type cap) {
            capacity(cap);
            allocate();
        }

        /**
         * @brief SecureArray initialized with data.
         *
         * The capacity is set to @c length if it is larger than the default capacity, stays at
         * default capacity if @c length is smaller than default capacity.
         */
        SecureArrayFlex(const_pointer data, size_type length) {
            if (length > capacity()) {
                capacity(length);
                allocate();
            }
            assign(data, length);
        }

        /**
         * @brief Copy constructor.
         */
        SecureArrayFlex(const SecureArrayFlex &other) {
            reset();
            capacity(other.capacity());
            allocate();
            assign(other);
        }

        /**
         * @brief Move constructor.
         */
        SecureArrayFlex(SecureArrayFlex&& other) noexcept {
            capacity(other.capacity());
            size(other.size());

            // array is larger than pre-allocated thus was allocated on heap. Just steal the pointer
            // and set it to pre-allocated on moved secure array, then set other values to initial states.
            if (other.data() != other.preAllocated()) {
                data(other.data());
                other.data(other.preAllocated());
            } else {
                memcpy(data(), other.data(), size() * sizeof(value_type));
            }
            other.capacity(SECURE_PRE_ALLOCATED);
            other.clear();
        }

        ~SecureArrayFlex() { reset(); }

        auto
        operator=(const SecureArrayFlex &x) -> SecureArrayFlex & {
            if (this != &x) {
                assign(x);
            }
            return *this;
        }

        [[nodiscard]] auto
        size() const -> size_type override { return size_; }

        [[nodiscard]] virtual auto
        capacity() const -> size_type const override { return capacity_; }

        auto
        data() noexcept -> pointer override { return data_; }

        [[nodiscard]] auto
        data() const noexcept -> const_pointer override { return data_; }

    private:
        auto
        size(size_type newSize) -> void override {
            size_ = newSize;
        }

        auto
        capacity(size_type cap) -> void override { capacity_ = cap; }

        auto
        data(pointer data) -> void override { data_ = data; }

        auto
        preAllocated() -> pointer override { return preAllocated_; }

        // reset the class to its initial state. Clear data, return to heap if necessary, set
        // to pre-allocated data, size to 0 and capacity to defined pre-allocated size.
        auto
        reset() -> void {
            clear();
            capacity_ = SECURE_PRE_ALLOCATED;
            if (data_ != preAllocated_) {
                delete[] data_;
                data_ = preAllocated_;
            }
        }

        auto allocate() -> void {
            if (capacity_ > SECURE_PRE_ALLOCATED) {
                data_ = new value_type[capacity_];
                wipeMemory(data_, capacity_ * sizeof(value_type));
            }
        }

        size_type size_ = 0;
        size_type capacity_ = SECURE_PRE_ALLOCATED;
        value_type preAllocated_[SECURE_PRE_ALLOCATED] = {0};
        pointer data_ = preAllocated_;
    };


    /**
     * @brief Secure array with a fixed size capacity.
     *
     * @tparam CAPACITY length of the secure array
     */
    template <size_t CAPACITY>
    class SecureArray : public SecureArrayBase {

    public:
        SecureArray() = default;

        auto
        capacity() const -> size_type const override { return CAPACITY; }

        SecureArray(const_pointer data, size_type length) {
            assign(data, length);
        }

        SecureArray(const SecureArray &other) {
            assign(other);
        }

        SecureArray(SecureArray&& other) noexcept {
            size(other.size());
            memcpy(data(), other.data(), size() * sizeof(value_type));
            other.clear();
        }

        ~SecureArray() { reset(); }

        auto
        operator=(const SecureArray &x) -> SecureArray & {
            if (this != &x) {
                assign(x);
            }
            return *this;
        }

        [[nodiscard]] auto
        size() const -> size_type override { return size_; }
        
        auto
        data() noexcept -> pointer override { return preAllocated(); }

        [[nodiscard]] auto
        data() const noexcept -> const_pointer override { return preAllocated(); }

    private:
        auto
        size(size_type newSize) -> void override {
            size_ = newSize;
        }

        auto
        capacity(size_type cap) -> void override {}    // Capacity is fixed

        auto
        data(pointer data) -> void override {}         // data array is fixed

        auto
        preAllocated() -> pointer override { return preAllocated_; }

        auto
        preAllocated() const -> const_pointer { return preAllocated_; }

        // reset the class to its initial state. Clear data, size to 0.
        auto
        reset() -> void {
            clear();
        }

        size_type size_ = 0;
        value_type preAllocated_[CAPACITY] = {0};
    };
}

/**
 * @}
 */
#endif //SEC_UTILS_SECURE_ARRAY_H
