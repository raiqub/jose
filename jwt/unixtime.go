/*
 * Copyright 2016 Fabrício Godoy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt

import "time"

// A UnixTime represents an instant in time from the number of seconds elapsed
// since January 1, 1970 UTC.
type UnixTime int64

// NewUnixTime create a new instance of UnixTime from Time.
func NewUnixTime(dt time.Time) UnixTime {
	return UnixTime(dt.Unix())
}

// ToTime returns a Time instance that represents same instant in time of
// current instance.
func (ut UnixTime) ToTime() time.Time {
	return time.Unix(int64(ut), 0)
}
