<?php

/**
 * Copyright 2014 Liam Williams
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 // This class is full of stubs to allow upgrades to go smoothly.
abstract class LiamW_AlterEgoDetector_Addon
{
    public static function install($installedAddon) {}
    public static function uninstall() {}   
    public static function extendClass($class, array &$extend){}
    public static function initDependencies(XenForo_Dependencies_Abstract $dependencies, array $data){}
    public static function extendLoginController($class, array &$extend){}
    public static function extendRegisterController($class, array &$extend){}
    public static function extendUserDataWriter($class, array &$extend){}
}
