/* World Bank specific business logic.
 */

#ifndef __WORLDBANK_HH__
#define __WORLDBANK_HH__
#pragma once

#include <cmath>
#include <cstdint>

namespace worldbank
{

static inline
double
round_half_up (double x)
{
	return std::floor (x + 0.5);
}

/* mantissa of 10E2
 */
static inline
int64_t
mantissa (double x)
{
	return (int64_t) round_half_up (x * 100.0);
}

/* round a double value to 2 decimal places using round half up
 */
static inline
double
round (double x)
{
	return (double) mantissa (x) / 100.0;
}

} // namespace worldbank

#endif /* __WORLDBANK_HH__ */

/* eof */
