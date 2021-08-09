/*
  ARG BUFFER
    take in data from arguments
*/

// Takes as argument NSArray and returns
// an unsigned char* referencing the byte
// contents of the argument array and a
// writes the length to a len variable
#define RN_ARG_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length;

// Same as above, except argument length is checked
#define RN_ARG_BUFFER(arg, len_check, error) \
  RN_ARG_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

// Same as above, except argument length is bounded
#define RN_ARG_BUFFER_MIN_MAX(arg, min, max, error) \
  RN_ARG_BUFFER_NO_CHECK(arg) \
  if (arg##len < min || arg##len > max) return error;

// Same as RN_ARG_BUFFER, except NULL arguments
// are treated as a zero-length array
#define RN_ARG_BUFFER_OR_NULL(arg) \
  NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned long arg##len = arg##_ns.length; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  if (arg##len == 0) arg##_data = NULL;

// Same as RN_ARG_BUFFER_NULL, except
// non-NULL arguments are bound checked
#define RN_ARG_BUFFER_MIN_MAX_OR_NULL(arg, min, max, error) \
  NSData *arg##_ns = [ self to_bytes: arg ]; \
  unsigned long arg##len = arg##_ns.length; \
  unsigned char *arg##_data = (unsigned char *) [ arg##_ns bytes ]; \
  if (arg##len == 0) arg##_data = NULL; \
  else if (arg##len < min || arg##len > max) return error;

// Same as RN_ARG_BUFFER, except (const char *) is returned
#define RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  const char *arg##_data = (const char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length; \

// Same as RN_ARG_CONST_BUFFER, except arguments are length checked
#define RN_ARG_CONST_BUFFER(arg, len_check, error) \
  RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;

// Same as RN_ARG_BUFFER_MIN_MAX, except (const char *) is returned
#define RN_ARG_CONST_BUFFER_MIN_MAX(arg, min, max, error) \
  RN_ARG_CONST_BUFFER_NO_CHECK(arg) \
  if (arg##len < min || arg##len > max) return error;

// Same as RN_ARG_BUFFER_NO_CHECK, except (const unsigned char *) is returned
#define RN_ARG_UCONST_BUFFER_NO_CHECK(arg) \
  const NSData *arg##_ns = [ self to_bytes: arg ]; \
  const unsigned char *arg##_data = (const unsigned char *) [ arg##_ns bytes ]; \
  unsigned long arg##len = arg##_ns.length; \

// Same as RN_ARG_BUFFER, except (const unsigned char *) is returned
#define RN_ARG_UCONST_BUFFER(arg, len_check, error) \
  RN_ARG_UCONST_BUFFER_NO_CHECK(arg) \
  if (arg##len != len_check) return error;


/*
  RESULT BUFFER
    empty buffer that results can be written to
    arglen may be written to by libsodium
*/

// Takes as argument NSArray and returns
// an empty buffer and a len pointer
// for return data to be written to.
#define RN_RESULT_BUFFER_NO_CHECK(arg) \
  unsigned long long arg##len = [arg count]; \
  unsigned char *arg##_data = (unsigned char *) sodium_malloc([ arg count ]); \
  if (arg##_data == NULL) return ERR_FAILURE;

// Same as above, except input length is checked
#define RN_RESULT_BUFFER(arg, length, error) \
  if ([arg count] != length) return error; \
  RN_RESULT_BUFFER_NO_CHECK(arg)

// Same as above, except input length is bounded
#define RN_RESULT_BUFFER_MIN_MAX(arg, min, max, error) \
  if ([arg count] < min || [arg count] > max) return error; \
  RN_RESULT_BUFFER_NO_CHECK(arg)


/*
  NUMBERS
*/

// Takes NSNumber and returns unsigned long long
#define RN_ULL(arg, min, max, error) \
  unsigned long long arg##_val = [arg unsignedLongLongValue];

// Takes NSNumber and returns int
#define RN_INT(arg, min, max, error) \
  int arg##_val = [arg intValue];

// Takes NSNumber and returns unsigned long long,
// with the result being bound checked.
#define RN_ULL_MIN_MAX(arg, min, max, error) \
  unsigned long long arg##_val = [arg unsignedLongLongValue]; \
  if (arg##_val < min || arg##_val > max) return error;

// Takes NSNumber and returns int,
// with the result being bound checked.
#define RN_INT_MIN_MAX(arg, min, max, error) \
  int arg##_val = [arg intValue]; \
  if (arg##_val < min || arg##_val > max) return error;


/*
  FUNCTION CALLS
*/

// Call a function and check the return value is 0.
#define RN_CHECK_FAILURE(call) \
  int result = call; \
  if (result != 0) return ERR_FAILURE;


/*
  RETURN DATA
    return bytes from ObjC to React-Native
*/

// Writes bytes back into the NSArray
// originally passed to the function
#define RN_RETURN_BUFFER(arg) \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: arg##len]; \
  RN_COPY_DATA(res, arg, arg##len) \
  return [res copy];

// For cases when multiple return values are needed,
// 2 buffers are concatenated and returned to RN.
// The first buffer must be of constant length.
// It is assumed the higher application understands
// how to parse the result
#define RN_RETURN_BUFFERS_2(buf1, buf2, b2len) \
  unsigned long long len = buf1##len + b2len; \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: len]; \
  RN_COPY_DATA(res, buf1, buf1##len) \
  RN_COPY_DATA(res, buf2, b2len) \
  return [res copy];

// Same as RN_RETURN_BUFFERS_2, except 3 buffers are
// concatenated. First 2 buffers must be of fixed length.
#define RN_RETURN_BUFFERS_3(buf1, buf2, buf3, b3len) \
  unsigned long long len = buf1##len + buf2##len + b3len; \
  NSMutableArray *res = [[NSMutableArray alloc] initWithCapacity: len]; \
  RN_COPY_DATA(res, buf1, buf1##len) \
  RN_COPY_DATA(res, buf2, buf2##len) \
  RN_COPY_DATA(res, buf3, b3len) \
  return [res copy];

// Copy data from (unsigned char *) to an NSArray
#define RN_COPY_DATA(res, buf, len) \
  for (int i = 0; i < len; i++) \
  { \
      [res addObject: [NSNumber numberWithUnsignedChar:buf##_data[i]]]; \
  }
