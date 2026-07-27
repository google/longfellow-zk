// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

macro_rules! arch_select {
    (
        $(
            if #[cfg($($meta:tt)*)] {
                mod $mod_name:ident;
            }
        )*
        else {
            mod $fallback_mod:ident;
        }
    ) => {
        $(
            #[cfg(all(not(feature = "force-generic-arch"), $($meta)*))]
            mod $mod_name;
            #[cfg(all(not(feature = "force-generic-arch"), $($meta)*))]
            pub use $mod_name::*;
        )*

        #[cfg(any(
            feature = "force-generic-arch",
            not(any($( all($($meta)*) ),*))
        ))]
        mod $fallback_mod;
        #[cfg(any(
            feature = "force-generic-arch",
            not(any($( all($($meta)*) ),*))
        ))]
        pub use $fallback_mod::*;
    };
}

arch_select! {
    if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "pclmulqdq",
        target_feature = "sse2"
    ))] {
        mod x86_64;
    }
    if #[cfg(target_arch = "aarch64")] {
        mod aarch64;
    }
    if #[cfg(all(
        target_arch = "arm",
        target_feature = "neon"
    ))] {
        mod arm_neon;
    }
    else {
        mod generic;
    }
}
