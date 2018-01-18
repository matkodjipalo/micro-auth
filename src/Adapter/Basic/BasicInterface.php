<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
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
