<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter\Basic;

use Micro\Auth\Adapter\AdapterInterface;

interface BasicInterface extends AdapterInterface
{
    /**
     * Plain authentication using username and password.
     *
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    public function plainAuth(string $username, string $password);
}
