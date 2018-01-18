<?php

declare(strict_types=1);

/**
 * balloon
 *
 * @copyright   Copryright (c) 2012-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     GPL-3.0 https://opensource.org/licenses/GPL-3.0
 */

namespace Micro\Auth\Adapter;

interface AdapterInterface
{
    /**
     * Get attribute sync cache.
     *
     * @return int
     */
    public function getAttributeSyncCache(): int;

    /**
     * Authenticate.
     *
     * @return bool
     */
    public function authenticate(): bool;

    /**
     * Get unqiue identity name.
     *
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * Get attribute map.
     *
     * @return iterable
     */
    public function getAttributeMap(): Iterable;

    /**
     * Get identity attributes.
     *
     * @return array
     */
    public function getAttributes(): array;
}
